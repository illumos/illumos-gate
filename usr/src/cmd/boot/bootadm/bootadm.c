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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * bootadm(1M) is a new utility for managing bootability of
 * Solaris *Newboot* environments. It has two primary tasks:
 * 	- Allow end users to manage bootability of Newboot Solaris instances
 *	- Provide services to other subsystems in Solaris (primarily Install)
 */

/* Headers */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mnttab.h>
#include <sys/statvfs.h>
#include <libnvpair.h>
#include <ftw.h>
#include <fcntl.h>
#include <strings.h>
#include <utime.h>
#include <sys/systeminfo.h>
#include <sys/dktp/fdisk.h>
#include <sys/param.h>
#if defined(__i386)
#include <sys/ucode.h>
#endif

#include <pwd.h>
#include <grp.h>
#include <device_info.h>

#include <locale.h>

#include <assert.h>

#include "message.h"
#include "bootadm.h"

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif	/* TEXT_DOMAIN */

/* Type definitions */

/* Primary subcmds */
typedef enum {
	BAM_MENU = 3,
	BAM_ARCHIVE
} subcmd_t;

typedef enum {
    OPT_ABSENT = 0,	/* No option */
    OPT_REQ,		/* option required */
    OPT_OPTIONAL	/* option may or may not be present */
} option_t;

typedef struct {
	char	*subcmd;
	option_t option;
	error_t (*handler)();
	int	unpriv;			/* is this an unprivileged command */
} subcmd_defn_t;

#define	LINE_INIT	0	/* lineNum initial value */
#define	ENTRY_INIT	-1	/* entryNum initial value */
#define	ALL_ENTRIES	-2	/* selects all boot entries */

#define	GRUB_DIR		"/boot/grub"
#define	GRUB_MENU		"/boot/grub/menu.lst"
#define	MENU_TMP		"/boot/grub/menu.lst.tmp"
#define	RAMDISK_SPECIAL		"/ramdisk"
#define	STUBBOOT		"/stubboot"

/* lock related */
#define	BAM_LOCK_FILE		"/var/run/bootadm.lock"
#define	LOCK_FILE_PERMS		(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#define	CREATE_RAMDISK		"/boot/solaris/bin/create_ramdisk"
#define	CREATE_DISKMAP		"/boot/solaris/bin/create_diskmap"
#define	GRUBDISK_MAP		"/var/run/solaris_grubdisk.map"

#define	GRUB_slice		"/etc/lu/GRUB_slice"
#define	GRUB_root		"/etc/lu/GRUB_root"
#define	GRUB_backup_menu	"/etc/lu/GRUB_backup_menu"
#define	GRUB_slice_mntpt	"/tmp/GRUB_slice_mntpt"
#define	LU_ACTIVATE_FILE	"/etc/lu/DelayUpdate/activate.sh"
#define	GRUB_fdisk		"/etc/lu/GRUB_fdisk"
#define	GRUB_fdisk_target	"/etc/lu/GRUB_fdisk_target"

#define	INSTALLGRUB		"/sbin/installgrub"
#define	STAGE1			"/boot/grub/stage1"
#define	STAGE2			"/boot/grub/stage2"

/*
 * The following two defines are used to detect and create the correct
 * boot archive  when safemode patching is underway.  LOFS_PATCH_FILE is a
 * contracted private interface between bootadm and the install
 * consolidation.  It is set by pdo.c when a patch with SUNW_PATCH_SAFEMODE
 * is applied.
 */

#define	LOFS_PATCH_FILE		"/var/run/.patch_loopback_mode"
#define	LOFS_PATCH_MNT		"/var/run/.patch_root_loopbackmnt"

/*
 * Default file attributes
 */
#define	DEFAULT_DEV_MODE	0644	/* default permissions */
#define	DEFAULT_DEV_UID		0	/* user root */
#define	DEFAULT_DEV_GID		3	/* group sys */

/*
 * Menu related
 * menu_cmd_t and menu_cmds must be kept in sync
 */
char *menu_cmds[] = {
	"default",	/* DEFAULT_CMD */
	"timeout",	/* TIMEOUT_CMD */
	"title",	/* TITLE_CMD */
	"root",		/* ROOT_CMD */
	"kernel",	/* KERNEL_CMD */
	"kernel$",	/* KERNEL_DOLLAR_CMD */
	"module",	/* MODULE_CMD */
	"module$",	/* MODULE_DOLLAR_CMD */
	" ",		/* SEP_CMD */
	"#",		/* COMMENT_CMD */
	"chainloader",	/* CHAINLOADER_CMD */
	"args",		/* ARGS_CMD */
	NULL
};

#define	OPT_ENTRY_NUM	"entry"

/*
 * archive related
 */
typedef struct {
	line_t *head;
	line_t *tail;
} filelist_t;

#define	BOOT_FILE_LIST	"boot/solaris/filelist.ramdisk"
#define	ETC_FILE_LIST	"etc/boot/solaris/filelist.ramdisk"

#define	FILE_STAT	"boot/solaris/filestat.ramdisk"
#define	FILE_STAT_TMP	"boot/solaris/filestat.ramdisk.tmp"
#define	DIR_PERMS	(S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)
#define	FILE_STAT_MODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

/* Globals */
int bam_verbose;
int bam_force;
static char *prog;
static subcmd_t bam_cmd;
static char *bam_root;
static int bam_rootlen;
static int bam_root_readonly;
static int bam_alt_root;
static char *bam_subcmd;
static char *bam_opt;
static int bam_debug;
static char **bam_argv;
static int bam_argc;
static int bam_check;
static int bam_smf_check;
static int bam_lock_fd = -1;
static char rootbuf[PATH_MAX] = "/";
static int bam_update_all;

/* function prototypes */
static void parse_args_internal(int argc, char *argv[]);
static void parse_args(int argc, char *argv[]);
static error_t bam_menu(char *subcmd, char *opt, int argc, char *argv[]);
static error_t bam_archive(char *subcmd, char *opt);

static void bam_print(char *format, ...);
static void bam_exit(int excode);
static void bam_lock(void);
static void bam_unlock(void);

static int exec_cmd(char *cmdline, char *output, int64_t osize);
static error_t read_globals(menu_t *mp, char *menu_path,
    char *globalcmd, int quiet);

static menu_t *menu_read(char *menu_path);
static error_t menu_write(char *root, menu_t *mp);
static void linelist_free(line_t *start);
static void menu_free(menu_t *mp);
static void line_free(line_t *lp);
static void filelist_free(filelist_t *flistp);
static error_t list2file(char *root, char *tmp,
    char *final, line_t *start);
static error_t list_entry(menu_t *mp, char *menu_path, char *opt);
static error_t delete_all_entries(menu_t *mp, char *menu_path, char *opt);
static error_t update_entry(menu_t *mp, char *root, char *opt);
static error_t update_temp(menu_t *mp, char *root, char *opt);

static error_t update_archive(char *root, char *opt);
static error_t list_archive(char *root, char *opt);
static error_t update_all(char *root, char *opt);
static error_t read_list(char *root, filelist_t  *flistp);
static error_t set_global(menu_t *mp, char *globalcmd, int val);
static error_t set_option(menu_t *mp, char *globalcmd, char *opt);
static error_t set_kernel(menu_t *mp, menu_cmd_t optnum, char *path,
    char *buf, size_t bufsize);
static char *expand_path(const char *partial_path);

static long s_strtol(char *str);
static int s_fputs(char *str, FILE *fp);

static char *s_strdup(char *str);
static int is_readonly(char *);
static int is_amd64(void);
static void append_to_flist(filelist_t *, char *);

#if defined(__sparc)
static void sparc_abort(void);
#endif

#if defined(__i386)
static void ucode_install();
#endif

/* Menu related sub commands */
static subcmd_defn_t menu_subcmds[] = {
	"set_option",		OPT_OPTIONAL,	set_option, 0,	/* PUB */
	"list_entry",		OPT_OPTIONAL,	list_entry, 1,	/* PUB */
	"delete_all_entries",	OPT_ABSENT,	delete_all_entries, 0, /* PVT */
	"update_entry",		OPT_REQ,	update_entry, 0, /* menu */
	"update_temp",		OPT_OPTIONAL,	update_temp, 0,	/* reboot */
	"upgrade",		OPT_ABSENT,	upgrade_menu, 0, /* menu */
	NULL,			0,		NULL, 0	/* must be last */
};

/* Archive related sub commands */
static subcmd_defn_t arch_subcmds[] = {
	"update",		OPT_ABSENT,	update_archive, 0, /* PUB */
	"update_all",		OPT_ABSENT,	update_all, 0,	/* PVT */
	"list",			OPT_OPTIONAL,	list_archive, 1, /* PUB */
	NULL,			0,		NULL, 0	/* must be last */
};

static struct {
	nvlist_t *new_nvlp;
	nvlist_t *old_nvlp;
	int need_update;
} walk_arg;


struct safefile {
	char *name;
	struct safefile *next;
};

static struct safefile *safefiles = NULL;
#define	NEED_UPDATE_FILE "/etc/svc/volatile/boot_archive_needs_update"

static void
usage(void)
{
	(void) fprintf(stderr, "USAGE:\n");


	/* archive usage */
	(void) fprintf(stderr, "\t%s update-archive [-vn] [-R altroot]\n",
	    prog);
	(void) fprintf(stderr, "\t%s list-archive [-R altroot]\n", prog);
#ifndef __sparc
	/* x86 only */
	(void) fprintf(stderr, "\t%s set-menu [-R altroot] key=value\n", prog);
	(void) fprintf(stderr, "\t%s list-menu [-R altroot]\n", prog);
#endif
}

int
main(int argc, char *argv[])
{
	error_t ret;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL) {
		prog = argv[0];
	} else {
		prog++;
	}


	/*
	 * Don't depend on caller's umask
	 */
	(void) umask(0022);

	parse_args(argc, argv);

#if defined(__sparc)
	/*
	 * There are only two valid invocations of bootadm
	 * on SPARC:
	 *
	 *	- SPARC diskless server creating boot_archive for i386 clients
	 *	- archive creation call during reboot of a SPARC system
	 *
	 *	The latter should be a NOP
	 */
	if (bam_cmd != BAM_ARCHIVE) {
		sparc_abort();
	}
#endif

	switch (bam_cmd) {
		case BAM_MENU:
			ret = bam_menu(bam_subcmd, bam_opt, bam_argc, bam_argv);
			break;
		case BAM_ARCHIVE:
			ret = bam_archive(bam_subcmd, bam_opt);
			break;
		default:
			usage();
			bam_exit(1);
	}

	if (ret != BAM_SUCCESS)
		bam_exit(1);

	bam_unlock();
	return (0);
}

#if defined(__sparc)

static void
sparc_abort(void)
{
	bam_error(NOT_ON_SPARC);
	bam_exit(1);
}

#endif

/*
 * Equivalence of public and internal commands:
 *	update-archive  -- -a update
 *	list-archive	-- -a list
 *	set-menu	-- -m set_option
 *	list-menu	-- -m list_entry
 *	update-menu	-- -m update_entry
 */
static struct cmd_map {
	char *bam_cmdname;
	int bam_cmd;
	char *bam_subcmd;
} cmd_map[] = {
	{ "update-archive",	BAM_ARCHIVE,	"update"},
	{ "list-archive",	BAM_ARCHIVE,	"list"},
	{ "set-menu",		BAM_MENU,	"set_option"},
	{ "list-menu",		BAM_MENU,	"list_entry"},
	{ "update-menu",	BAM_MENU,	"update_entry"},
	{ NULL,			0,		NULL}
};

/*
 * Commands syntax published in bootadm(1M) are parsed here
 */
static void
parse_args(int argc, char *argv[])
{
	struct cmd_map *cmp = cmd_map;

	/* command conforming to the final spec */
	if (argc > 1 && argv[1][0] != '-') {
		/*
		 * Map commands to internal table.
		 */
		while (cmp->bam_cmdname) {
			if (strcmp(argv[1], cmp->bam_cmdname) == 0) {
				bam_cmd = cmp->bam_cmd;
				bam_subcmd = cmp->bam_subcmd;
				break;
			}
			cmp++;
		}
		if (cmp->bam_cmdname == NULL) {
			usage();
			bam_exit(1);
		}
		argc--;
		argv++;
	}

	parse_args_internal(argc, argv);
}

/*
 * A combination of public and private commands are parsed here.
 * The internal syntax and the corresponding functionality are:
 *	-a update	-- update-archive
 *	-a list		-- list-archive
 *	-a update-all	-- (reboot to sync all mounted OS archive)
 *	-m update_entry	-- update-menu
 *	-m list_entry	-- list-menu
 *	-m update_temp	-- (reboot -- [boot-args])
 *	-m delete_all_entries -- (called from install)
 */
static void
parse_args_internal(int argc, char *argv[])
{
	int c, error;
	extern char *optarg;
	extern int optind, opterr;

	/* Suppress error message from getopt */
	opterr = 0;

	error = 0;
	while ((c = getopt(argc, argv, "a:d:fm:no:vCR:")) != -1) {
		switch (c) {
		case 'a':
			if (bam_cmd) {
				error = 1;
				bam_error(MULT_CMDS, c);
			}
			bam_cmd = BAM_ARCHIVE;
			bam_subcmd = optarg;
			break;
		case 'd':
			if (bam_debug) {
				error = 1;
				bam_error(DUP_OPT, c);
			}
			bam_debug = s_strtol(optarg);
			break;
		case 'f':
			if (bam_force) {
				error = 1;
				bam_error(DUP_OPT, c);
			}
			bam_force = 1;
			break;
		case 'm':
			if (bam_cmd) {
				error = 1;
				bam_error(MULT_CMDS, c);
			}
			bam_cmd = BAM_MENU;
			bam_subcmd = optarg;
			break;
		case 'n':
			if (bam_check) {
				error = 1;
				bam_error(DUP_OPT, c);
			}
			bam_check = 1;
			break;
		case 'o':
			if (bam_opt) {
				error = 1;
				bam_error(DUP_OPT, c);
			}
			bam_opt = optarg;
			break;
		case 'v':
			if (bam_verbose) {
				error = 1;
				bam_error(DUP_OPT, c);
			}
			bam_verbose = 1;
			break;
		case 'C':
			bam_smf_check = 1;
			break;
		case 'R':
			if (bam_root) {
				error = 1;
				bam_error(DUP_OPT, c);
				break;
			} else if (realpath(optarg, rootbuf) == NULL) {
				error = 1;
				bam_error(CANT_RESOLVE, optarg,
				    strerror(errno));
				break;
			}
			bam_alt_root = 1;
			bam_root = rootbuf;
			bam_rootlen = strlen(rootbuf);
			break;
		case '?':
			error = 1;
			bam_error(BAD_OPT, optopt);
			break;
		default :
			error = 1;
			bam_error(BAD_OPT, c);
			break;
		}
	}

	/*
	 * A command option must be specfied
	 */
	if (!bam_cmd) {
		if (bam_opt && strcmp(bam_opt, "all") == 0) {
			usage();
			bam_exit(0);
		}
		bam_error(NEED_CMD);
		error = 1;
	}

	if (error) {
		usage();
		bam_exit(1);
	}

	if (optind > argc) {
		bam_error(INT_ERROR, "parse_args");
		bam_exit(1);
	} else if (optind < argc) {
		bam_argv = &argv[optind];
		bam_argc = argc - optind;
	}

	/*
	 * -n implies verbose mode
	 */
	if (bam_check)
		bam_verbose = 1;
}

static error_t
check_subcmd_and_options(
	char *subcmd,
	char *opt,
	subcmd_defn_t *table,
	error_t (**fp)())
{
	int i;

	if (subcmd == NULL) {
		bam_error(NEED_SUBCMD);
		return (BAM_ERROR);
	}

	if (bam_argc != 0 || bam_argv) {
		if (strcmp(subcmd, "set_option") != 0 || bam_argc != 1) {
			bam_error(TRAILING_ARGS);
			usage();
			return (BAM_ERROR);
		}
	}

	if (bam_root == NULL) {
		bam_root = rootbuf;
		bam_rootlen = 1;
	}

	/* verify that subcmd is valid */
	for (i = 0; table[i].subcmd != NULL; i++) {
		if (strcmp(table[i].subcmd, subcmd) == 0)
			break;
	}

	if (table[i].subcmd == NULL) {
		bam_error(INVALID_SUBCMD, subcmd);
		return (BAM_ERROR);
	}

	if (table[i].unpriv == 0 && geteuid() != 0) {
		bam_error(MUST_BE_ROOT);
		return (BAM_ERROR);
	}

	/*
	 * Currently only privileged commands need a lock
	 */
	if (table[i].unpriv == 0)
		bam_lock();

	/* subcmd verifies that opt is appropriate */
	if (table[i].option != OPT_OPTIONAL) {
		if ((table[i].option == OPT_REQ) ^ (opt != NULL)) {
			if (opt)
				bam_error(NO_OPT_REQ, subcmd);
			else
				bam_error(MISS_OPT, subcmd);
			return (BAM_ERROR);
		}
	}

	*fp = table[i].handler;

	return (BAM_SUCCESS);
}


static char *
mount_grub_slice(int *mnted, char **physlice, char **logslice, char **fs_type)
{
	struct extmnttab mnt;
	struct stat sb;
	char buf[BAM_MAXLINE], dev[PATH_MAX], phys[PATH_MAX], fstype[32];
	char cmd[PATH_MAX];
	char *mntpt;
	int p, l, f;
	FILE *fp;

	assert(mnted);
	*mnted = 0;

	/*
	 * physlice, logslice, fs_type  args may be NULL
	 */
	if (physlice)
		*physlice = NULL;
	if (logslice)
		*logslice = NULL;
	if (fs_type)
		*fs_type = NULL;

	if (stat(GRUB_slice, &sb) != 0) {
		bam_error(MISSING_SLICE_FILE, GRUB_slice, strerror(errno));
		return (NULL);
	}

	fp = fopen(GRUB_slice, "r");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, GRUB_slice, strerror(errno));
		return (NULL);
	}

	dev[0] = fstype[0] = phys[0] = '\0';
	p = sizeof ("PHYS_SLICE=") - 1;
	l = sizeof ("LOG_SLICE=") - 1;
	f = sizeof ("LOG_FSTYP=") - 1;
	while (s_fgets(buf, sizeof (buf), fp) != NULL) {
		if (strncmp(buf, "PHYS_SLICE=", p) == 0) {
			(void) strlcpy(phys, buf + p, sizeof (phys));
			continue;
		}
		if (strncmp(buf, "LOG_SLICE=", l) == 0) {
			(void) strlcpy(dev, buf + l, sizeof (dev));
			continue;
		}
		if (strncmp(buf, "LOG_FSTYP=", f) == 0) {
			(void) strlcpy(fstype, buf + f, sizeof (fstype));
			continue;
		}
	}
	(void) fclose(fp);

	if (dev[0] == '\0' || fstype[0] == '\0' || phys[0] == '\0') {
		bam_error(BAD_SLICE_FILE, GRUB_slice);
		return (NULL);
	}

	if (physlice) {
		*physlice = s_strdup(phys);
	}
	if (logslice) {
		*logslice = s_strdup(dev);
	}
	if (fs_type) {
		*fs_type = s_strdup(fstype);
	}

	/*
	 * Check if the slice is already mounted
	 */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, MNTTAB, strerror(errno));
		goto error;
	}

	resetmnttab(fp);

	mntpt = NULL;
	while (getextmntent(fp, &mnt, sizeof (mnt)) == 0) {
		if (strcmp(mnt.mnt_special, dev) == 0) {
			mntpt = s_strdup(mnt.mnt_mountp);
			break;
		}
	}

	(void) fclose(fp);

	if (mntpt) {
		return (mntpt);
	}


	/*
	 * GRUB slice is not mounted, we need to mount it now.
	 * First create the mountpoint
	 */
	mntpt = s_calloc(1, PATH_MAX);
	(void) snprintf(mntpt, PATH_MAX, "%s.%d", GRUB_slice_mntpt, getpid());
	if (mkdir(mntpt, 0755) == -1 && errno != EEXIST) {
		bam_error(MKDIR_FAILED, mntpt, strerror(errno));
		free(mntpt);
		goto error;
	}

	(void) snprintf(cmd, sizeof (cmd), "/sbin/mount -F %s %s %s",
	    fstype, dev, mntpt);

	if (exec_cmd(cmd, NULL, 0) != 0) {
		bam_error(MOUNT_FAILED, dev, fstype);
		if (rmdir(mntpt) != 0) {
			bam_error(RMDIR_FAILED, mntpt, strerror(errno));
		}
		free(mntpt);
		goto error;
	}

	*mnted = 1;
	return (mntpt);

error:
	if (physlice) {
		free(*physlice);
		*physlice = NULL;
	}
	if (logslice) {
		free(*logslice);
		*logslice = NULL;
	}
	if (fs_type) {
		free(*fs_type);
		*fs_type = NULL;
	}
	return (NULL);
}

static void
umount_grub_slice(
	int mnted,
	char *mntpt,
	char *physlice,
	char *logslice,
	char *fs_type)
{
	char cmd[PATH_MAX];

	/*
	 * If we have not dealt with GRUB slice
	 * we have nothing to do - just return.
	 */
	if (mntpt == NULL)
		return;


	/*
	 * If we mounted the filesystem earlier in mount_grub_slice()
	 * unmount it now.
	 */
	if (mnted) {
		(void) snprintf(cmd, sizeof (cmd), "/sbin/umount %s",
		    mntpt);
		if (exec_cmd(cmd, NULL, 0) != 0) {
			bam_error(UMOUNT_FAILED, mntpt);
		}
		if (rmdir(mntpt) != 0) {
			bam_error(RMDIR_FAILED, mntpt, strerror(errno));
		}
	}

	if (physlice)
		free(physlice);
	if (logslice)
		free(logslice);
	if (fs_type)
		free(fs_type);

	free(mntpt);
}

static char *
use_stubboot(void)
{
	int mnted;
	struct stat sb;
	struct extmnttab mnt;
	FILE *fp;
	char cmd[PATH_MAX];

	if (stat(STUBBOOT, &sb) != 0) {
		bam_error(STUBBOOT_DIR_NOT_FOUND);
		return (NULL);
	}

	/*
	 * Check if stubboot is mounted. If not, mount it
	 */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, MNTTAB, strerror(errno));
		return (NULL);
	}

	resetmnttab(fp);

	mnted = 0;
	while (getextmntent(fp, &mnt, sizeof (mnt)) == 0) {
		if (strcmp(mnt.mnt_mountp, STUBBOOT) == 0) {
			mnted = 1;
			break;
		}
	}

	(void) fclose(fp);

	if (mnted)
		return (STUBBOOT);

	/*
	 * Stubboot is not mounted, mount it now.
	 * It should exist in /etc/vfstab
	 */
	(void) snprintf(cmd, sizeof (cmd), "/sbin/mount %s",
	    STUBBOOT);
	if (exec_cmd(cmd, NULL, 0) != 0) {
		bam_error(MOUNT_MNTPT_FAILED, STUBBOOT);
		return (NULL);
	}

	return (STUBBOOT);
}

static void
disp_active_menu_locn(char *menu_path, char *logslice, char *fstype, int mnted)
{
	/*
	 * Check if we did a temp mount of an unmounted device.
	 * If yes, print the block device and fstype for that device
	 * else it is already mounted, so we print the path to the GRUB menu.
	 */
	if (mnted) {
		bam_print(GRUB_MENU_DEVICE, logslice);
		bam_print(GRUB_MENU_FSTYPE, fstype);
	} else {
		bam_print(GRUB_MENU_PATH, menu_path);
	}
}

/*
 * NOTE: A single "/" is also considered a trailing slash and will
 * be deleted.
 */
static void
elide_trailing_slash(const char *src, char *dst, size_t dstsize)
{
	size_t dstlen;

	assert(src);
	assert(dst);

	(void) strlcpy(dst, src, dstsize);

	dstlen = strlen(dst);
	if (dst[dstlen - 1] == '/') {
		dst[dstlen - 1] = '\0';
	}
}

static error_t
bam_menu(char *subcmd, char *opt, int largc, char *largv[])
{
	error_t ret;
	char menu_path[PATH_MAX];
	char path[PATH_MAX];
	menu_t *menu;
	char *mntpt, *menu_root, *logslice, *fstype;
	struct stat sb;
	int mnted;	/* set if we did a mount */
	error_t (*f)(menu_t *mp, char *menu_path, char *opt);

	/*
	 * Check arguments
	 */
	ret = check_subcmd_and_options(subcmd, opt, menu_subcmds, &f);
	if (ret == BAM_ERROR) {
		return (BAM_ERROR);
	}

	mntpt = NULL;
	mnted = 0;
	logslice = fstype = NULL;

	/*
	 * Check for the menu.list file:
	 *
	 * 1. Check for a GRUB_slice file, be it on / or
	 *    on the user-provided alternate root.
	 * 2. Use the alternate root, if given.
	 * 3. Check /stubboot
	 * 4. Use /
	 */
	if (bam_alt_root) {
		(void) snprintf(path, sizeof (path), "%s%s", bam_root,
		    GRUB_slice);
	} else {
		(void) snprintf(path, sizeof (path), "%s", GRUB_slice);
	}

	if (stat(path, &sb) == 0) {
		mntpt = mount_grub_slice(&mnted, NULL, &logslice, &fstype);
		menu_root = mntpt;
	} else if (bam_alt_root) {
		menu_root = bam_root;
	} else if (stat(STUBBOOT, &sb) == 0) {
		menu_root = use_stubboot();
	} else {
		menu_root = bam_root;
	}

	if (menu_root == NULL) {
		bam_error(CANNOT_LOCATE_GRUB_MENU);
		return (BAM_ERROR);
	}

	elide_trailing_slash(menu_root, menu_path, sizeof (menu_path));
	(void) strlcat(menu_path, GRUB_MENU, sizeof (menu_path));

	/*
	 * If listing the menu, display the active menu
	 * location
	 */
	if (strcmp(subcmd, "list_entry") == 0) {
		disp_active_menu_locn(menu_path, logslice, fstype, mnted);
	}

	menu = menu_read(menu_path);
	assert(menu);

	/*
	 * Special handling for setting timeout and default
	 */
	if (strcmp(subcmd, "set_option") == 0) {
		if (largc != 1 || largv[0] == NULL) {
			usage();
			menu_free(menu);
			umount_grub_slice(mnted, mntpt, NULL, logslice, fstype);
			return (BAM_ERROR);
		}
		opt = largv[0];
	} else if (largc != 0) {
		usage();
		menu_free(menu);
		umount_grub_slice(mnted, mntpt, NULL, logslice, fstype);
		return (BAM_ERROR);
	}

	ret = dboot_or_multiboot(bam_root);
	if (ret != BAM_SUCCESS)
		return (ret);

	/*
	 * Once the sub-cmd handler has run
	 * only the line field is guaranteed to have valid values
	 */
	if ((strcmp(subcmd, "update_entry") == 0) ||
	    (strcmp(subcmd, "upgrade") == 0))
		ret = f(menu, bam_root, opt);
	else
		ret = f(menu, menu_path, opt);
	if (ret == BAM_WRITE) {
		ret = menu_write(menu_root, menu);
	}

	menu_free(menu);

	umount_grub_slice(mnted, mntpt, NULL, logslice, fstype);

	return (ret);
}


static error_t
bam_archive(
	char *subcmd,
	char *opt)
{
	error_t ret;
	error_t (*f)(char *root, char *opt);

	/*
	 * Add trailing / for archive subcommands
	 */
	if (rootbuf[strlen(rootbuf) - 1] != '/')
		(void) strcat(rootbuf, "/");
	bam_rootlen = strlen(rootbuf);

	/*
	 * Check arguments
	 */
	ret = check_subcmd_and_options(subcmd, opt, arch_subcmds, &f);
	if (ret != BAM_SUCCESS) {
		return (BAM_ERROR);
	}

#if defined(__sparc)
	/*
	 * A NOP if called on SPARC during reboot
	 */
	if (strcmp(subcmd, "update_all") == 0)
		return (BAM_SUCCESS);
	else if (strcmp(subcmd, "update") != 0)
		sparc_abort();
#endif

	ret = dboot_or_multiboot(rootbuf);
	if (ret != BAM_SUCCESS)
		return (ret);

	/*
	 * Check archive not supported with update_all
	 * since it is awkward to display out-of-sync
	 * information for each BE.
	 */
	if (bam_check && strcmp(subcmd, "update_all") == 0) {
		bam_error(CHECK_NOT_SUPPORTED, subcmd);
		return (BAM_ERROR);
	}

	if (strcmp(subcmd, "update_all") == 0)
		bam_update_all = 1;

#if defined(__i386)
	ucode_install(bam_root);
#endif

	ret = f(bam_root, opt);

	bam_update_all = 0;

	return (ret);
}

/*PRINTFLIKE1*/
void
bam_error(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	(void) fprintf(stderr, "%s: ", prog);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
static void
bam_print(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	(void) vfprintf(stdout, format, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
bam_print_stderr(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
}

static void
bam_exit(int excode)
{
	bam_unlock();
	exit(excode);
}

static void
bam_lock(void)
{
	struct flock lock;
	pid_t pid;

	bam_lock_fd = open(BAM_LOCK_FILE, O_CREAT|O_RDWR, LOCK_FILE_PERMS);
	if (bam_lock_fd < 0) {
		/*
		 * We may be invoked early in boot for archive verification.
		 * In this case, root is readonly and /var/run may not exist.
		 * Proceed without the lock
		 */
		if (errno == EROFS || errno == ENOENT) {
			bam_root_readonly = 1;
			return;
		}

		bam_error(OPEN_FAIL, BAM_LOCK_FILE, strerror(errno));
		bam_exit(1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(bam_lock_fd, F_SETLK, &lock) == -1) {
		if (errno != EACCES && errno != EAGAIN) {
			bam_error(LOCK_FAIL, BAM_LOCK_FILE, strerror(errno));
			(void) close(bam_lock_fd);
			bam_lock_fd = -1;
			bam_exit(1);
		}
		pid = 0;
		(void) pread(bam_lock_fd, &pid, sizeof (pid_t), 0);
		bam_print(FILE_LOCKED, pid);

		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;
		lock.l_len = 0;
		if (fcntl(bam_lock_fd, F_SETLKW, &lock) == -1) {
			bam_error(LOCK_FAIL, BAM_LOCK_FILE, strerror(errno));
			(void) close(bam_lock_fd);
			bam_lock_fd = -1;
			bam_exit(1);
		}
	}

	/* We own the lock now */
	pid = getpid();
	(void) write(bam_lock_fd, &pid, sizeof (pid));
}

static void
bam_unlock(void)
{
	struct flock unlock;

	/*
	 * NOP if we don't hold the lock
	 */
	if (bam_lock_fd < 0) {
		return;
	}

	unlock.l_type = F_UNLCK;
	unlock.l_whence = SEEK_SET;
	unlock.l_start = 0;
	unlock.l_len = 0;

	if (fcntl(bam_lock_fd, F_SETLK, &unlock) == -1) {
		bam_error(UNLOCK_FAIL, BAM_LOCK_FILE, strerror(errno));
	}

	if (close(bam_lock_fd) == -1) {
		bam_error(CLOSE_FAIL, BAM_LOCK_FILE, strerror(errno));
	}
	bam_lock_fd = -1;
}

static error_t
list_archive(char *root, char *opt)
{
	filelist_t flist;
	filelist_t *flistp = &flist;
	line_t *lp;

	assert(root);
	assert(opt == NULL);

	flistp->head = flistp->tail = NULL;
	if (read_list(root, flistp) != BAM_SUCCESS) {
		return (BAM_ERROR);
	}
	assert(flistp->head && flistp->tail);

	for (lp = flistp->head; lp; lp = lp->next) {
		bam_print(PRINT, lp->line);
	}

	filelist_free(flistp);

	return (BAM_SUCCESS);
}

/*
 * This routine writes a list of lines to a file.
 * The list is *not* freed
 */
static error_t
list2file(char *root, char *tmp, char *final, line_t *start)
{
	char tmpfile[PATH_MAX];
	char path[PATH_MAX];
	FILE *fp;
	int ret;
	struct stat sb;
	mode_t mode;
	uid_t root_uid;
	gid_t sys_gid;
	struct passwd *pw;
	struct group *gp;


	(void) snprintf(path, sizeof (path), "%s%s", root, final);

	if (start == NULL) {
		if (stat(path, &sb) != -1) {
			bam_print(UNLINK_EMPTY, path);
			if (unlink(path) != 0) {
				bam_error(UNLINK_FAIL, path, strerror(errno));
				return (BAM_ERROR);
			} else {
				return (BAM_SUCCESS);
			}
		}
	}

	/*
	 * Preserve attributes of existing file if possible,
	 * otherwise ask the system for uid/gid of root/sys.
	 * If all fails, fall back on hard-coded defaults.
	 */
	if (stat(path, &sb) != -1) {
		mode = sb.st_mode;
		root_uid = sb.st_uid;
		sys_gid = sb.st_gid;
	} else {
		mode = DEFAULT_DEV_MODE;
		if ((pw = getpwnam(DEFAULT_DEV_USER)) != NULL) {
			root_uid = pw->pw_uid;
		} else {
			if (bam_verbose)
				bam_error(CANT_FIND_USER,
				    DEFAULT_DEV_USER, DEFAULT_DEV_UID);
			root_uid = (uid_t)DEFAULT_DEV_UID;
		}
		if ((gp = getgrnam(DEFAULT_DEV_GROUP)) != NULL) {
			sys_gid = gp->gr_gid;
		} else {
			if (bam_verbose)
				bam_error(CANT_FIND_GROUP,
				    DEFAULT_DEV_GROUP, DEFAULT_DEV_GID);
			sys_gid = (gid_t)DEFAULT_DEV_GID;
		}
	}

	(void) snprintf(tmpfile, sizeof (tmpfile), "%s%s", root, tmp);

	/* Truncate tmpfile first */
	fp = fopen(tmpfile, "w");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, tmpfile, strerror(errno));
		return (BAM_ERROR);
	}
	ret = fclose(fp);
	if (ret == EOF) {
		bam_error(CLOSE_FAIL, tmpfile, strerror(errno));
		return (BAM_ERROR);
	}

	/* Now open it in append mode */
	fp = fopen(tmpfile, "a");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, tmpfile, strerror(errno));
		return (BAM_ERROR);
	}

	for (; start; start = start->next) {
		ret = s_fputs(start->line, fp);
		if (ret == EOF) {
			bam_error(WRITE_FAIL, tmpfile, strerror(errno));
			(void) fclose(fp);
			return (BAM_ERROR);
		}
	}

	ret = fclose(fp);
	if (ret == EOF) {
		bam_error(CLOSE_FAIL, tmpfile, strerror(errno));
		return (BAM_ERROR);
	}

	/*
	 * Set up desired attributes.  Ignore failures on filesystems
	 * not supporting these operations - pcfs reports unsupported
	 * operations as EINVAL.
	 */
	ret = chmod(tmpfile, mode);
	if (ret == -1 &&
	    errno != EINVAL && errno != ENOTSUP) {
		bam_error(CHMOD_FAIL, tmpfile, strerror(errno));
		return (BAM_ERROR);
	}

	ret = chown(tmpfile, root_uid, sys_gid);
	if (ret == -1 &&
	    errno != EINVAL && errno != ENOTSUP) {
		bam_error(CHOWN_FAIL, tmpfile, strerror(errno));
		return (BAM_ERROR);
	}


	/*
	 * Do an atomic rename
	 */
	ret = rename(tmpfile, path);
	if (ret != 0) {
		bam_error(RENAME_FAIL, path, strerror(errno));
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

/*
 * This function should always return 0 - since we want
 * to create stat data for *all* files in the list.
 */
/*ARGSUSED*/
static int
cmpstat(
	const char *file,
	const struct stat *stat,
	int flags,
	struct FTW *ftw)
{
	uint_t sz;
	uint64_t *value;
	uint64_t filestat[2];
	int error;

	struct safefile *safefilep;
	FILE *fp;

	/*
	 * We only want regular files
	 */
	if (!S_ISREG(stat->st_mode))
		return (0);

	/*
	 * new_nvlp may be NULL if there were errors earlier
	 * but this is not fatal to update determination.
	 */
	if (walk_arg.new_nvlp) {
		filestat[0] = stat->st_size;
		filestat[1] = stat->st_mtime;
		error = nvlist_add_uint64_array(walk_arg.new_nvlp,
		    file + bam_rootlen, filestat, 2);
		if (error)
			bam_error(NVADD_FAIL, file, strerror(error));
	}

	/*
	 * The remaining steps are only required if we haven't made a
	 * decision about update or if we are checking (-n)
	 */
	if (walk_arg.need_update && !bam_check)
		return (0);

	/*
	 * If we are invoked as part of system/filesyste/boot-archive, then
	 * there are a number of things we should not worry about
	 */
	if (bam_smf_check) {
		/* ignore amd64 modules unless we are booted amd64. */
		if (!is_amd64() && strstr(file, "/amd64/") != 0)
			return (0);

		/* read in list of safe files */
		if (safefiles == NULL)
			if (fp = fopen("/boot/solaris/filelist.safe", "r")) {
				safefiles = s_calloc(1,
				    sizeof (struct safefile));
				safefilep = safefiles;
				safefilep->name = s_calloc(1, MAXPATHLEN +
				    MAXNAMELEN);
				safefilep->next = NULL;
				while (s_fgets(safefilep->name, MAXPATHLEN +
				    MAXNAMELEN, fp) != NULL) {
					safefilep->next = s_calloc(1,
					    sizeof (struct safefile));
					safefilep = safefilep->next;
					safefilep->name = s_calloc(1,
					    MAXPATHLEN + MAXNAMELEN);
					safefilep->next = NULL;
				}
				(void) fclose(fp);
			}
	}

	/*
	 * We need an update if file doesn't exist in old archive
	 */
	if (walk_arg.old_nvlp == NULL ||
	    nvlist_lookup_uint64_array(walk_arg.old_nvlp,
	    file + bam_rootlen, &value, &sz) != 0) {
		if (bam_smf_check)	/* ignore new during smf check */
			return (0);
		walk_arg.need_update = 1;
		if (bam_verbose)
			bam_print(PARSEABLE_NEW_FILE, file);
		return (0);
	}

	/*
	 * File exists in old archive. Check if file has changed
	 */
	assert(sz == 2);
	bcopy(value, filestat, sizeof (filestat));

	if (filestat[0] != stat->st_size ||
	    filestat[1] != stat->st_mtime) {
		if (bam_smf_check) {
			safefilep = safefiles;
			while (safefilep != NULL) {
				if (strcmp(file + bam_rootlen,
				    safefilep->name) == 0) {
					(void) creat(NEED_UPDATE_FILE, 0644);
					return (0);
				}
				safefilep = safefilep->next;
			}
		}
		walk_arg.need_update = 1;
		if (bam_verbose)
			if (bam_smf_check)
				bam_print("    %s\n", file);
			else
				bam_print(PARSEABLE_OUT_DATE, file);
	}

	return (0);
}

/*
 * Check flags and presence of required files.
 * The force flag and/or absence of files should
 * trigger an update.
 * Suppress stdout output if check (-n) option is set
 * (as -n should only produce parseable output.)
 */
static void
check_flags_and_files(char *root)
{
	char path[PATH_MAX];
	struct stat sb;

	/*
	 * if force, create archive unconditionally
	 */
	if (bam_force) {
		walk_arg.need_update = 1;
		if (bam_verbose && !bam_check)
			bam_print(UPDATE_FORCE);
		return;
	}

	/*
	 * If archive is missing, create archive
	 */
	(void) snprintf(path, sizeof (path), "%s%s", root,
	    DIRECT_BOOT_ARCHIVE_32);
	if (stat(path, &sb) != 0) {
		if (bam_verbose && !bam_check)
			bam_print(UPDATE_ARCH_MISS, path);
		walk_arg.need_update = 1;
		return;
	}
	if (bam_direct == BAM_DIRECT_DBOOT) {
		(void) snprintf(path, sizeof (path), "%s%s", root,
		    DIRECT_BOOT_ARCHIVE_64);
		if (stat(path, &sb) != 0) {
			if (bam_verbose && !bam_check)
				bam_print(UPDATE_ARCH_MISS, path);
			walk_arg.need_update = 1;
			return;
		}
	}
}

static error_t
read_one_list(char *root, filelist_t  *flistp, char *filelist)
{
	char path[PATH_MAX];
	FILE *fp;
	char buf[BAM_MAXLINE];

	(void) snprintf(path, sizeof (path), "%s%s", root, filelist);

	fp = fopen(path, "r");
	if (fp == NULL) {
		if (bam_debug)
			bam_error(FLIST_FAIL, path, strerror(errno));
		return (BAM_ERROR);
	}
	while (s_fgets(buf, sizeof (buf), fp) != NULL) {
		/* skip blank lines */
		if (strspn(buf, " \t") == strlen(buf))
			continue;
		append_to_flist(flistp, buf);
	}
	if (fclose(fp) != 0) {
		bam_error(CLOSE_FAIL, path, strerror(errno));
		return (BAM_ERROR);
	}
	return (BAM_SUCCESS);
}

static error_t
read_list(char *root, filelist_t  *flistp)
{
	int rval;

	flistp->head = flistp->tail = NULL;

	/*
	 * Read current lists of files - only the first is mandatory
	 */
	rval = read_one_list(root, flistp, BOOT_FILE_LIST);
	if (rval != BAM_SUCCESS)
		return (rval);
	(void) read_one_list(root, flistp, ETC_FILE_LIST);

	if (flistp->head == NULL) {
		bam_error(NO_FLIST);
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

static void
getoldstat(char *root)
{
	char path[PATH_MAX];
	int fd, error;
	struct stat sb;
	char *ostat;

	(void) snprintf(path, sizeof (path), "%s%s", root, FILE_STAT);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (bam_verbose)
			bam_print(OPEN_FAIL, path, strerror(errno));
		walk_arg.need_update = 1;
		return;
	}

	if (fstat(fd, &sb) != 0) {
		bam_error(STAT_FAIL, path, strerror(errno));
		(void) close(fd);
		walk_arg.need_update = 1;
		return;
	}

	ostat = s_calloc(1, sb.st_size);

	if (read(fd, ostat, sb.st_size) != sb.st_size) {
		bam_error(READ_FAIL, path, strerror(errno));
		(void) close(fd);
		free(ostat);
		walk_arg.need_update = 1;
		return;
	}

	(void) close(fd);

	walk_arg.old_nvlp = NULL;
	error = nvlist_unpack(ostat, sb.st_size, &walk_arg.old_nvlp, 0);

	free(ostat);

	if (error) {
		bam_error(UNPACK_FAIL, path, strerror(error));
		walk_arg.old_nvlp = NULL;
		walk_arg.need_update = 1;
		return;
	}
}

/*
 * Checks if a file in the current (old) archive has
 * been deleted from the root filesystem. This is needed for
 * software like Trusted Extensions (TX) that switch early
 * in boot based on presence/absence of a kernel module.
 */
static void
check4stale(char *root)
{
	nvpair_t	*nvp;
	nvlist_t	*nvlp;
	char 		*file;
	char		path[PATH_MAX];
	struct stat	sb;

	/*
	 * Skip stale file check during smf check
	 */
	if (bam_smf_check)
		return;

	/* Nothing to do if no old stats */
	if ((nvlp = walk_arg.old_nvlp) == NULL)
		return;

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {
		file = nvpair_name(nvp);
		if (file == NULL)
			continue;
		(void) snprintf(path, sizeof (path), "%s/%s",
		    root, file);
		if (stat(path, &sb) == -1) {
			walk_arg.need_update = 1;
			if (bam_verbose)
				bam_print(PARSEABLE_STALE_FILE, path);
		}
	}
}

static void
create_newstat(void)
{
	int error;

	error = nvlist_alloc(&walk_arg.new_nvlp, NV_UNIQUE_NAME, 0);
	if (error) {
		/*
		 * Not fatal - we can still create archive
		 */
		walk_arg.new_nvlp = NULL;
		bam_error(NVALLOC_FAIL, strerror(error));
	}
}

static void
walk_list(char *root, filelist_t *flistp)
{
	char path[PATH_MAX];
	line_t *lp;

	for (lp = flistp->head; lp; lp = lp->next) {
		(void) snprintf(path, sizeof (path), "%s%s", root, lp->line);
		/* XXX shouldn't we use FTW_MOUNT ? */
		if (nftw(path, cmpstat, 20, 0) == -1) {
			/*
			 * Some files may not exist.
			 * For example: etc/rtc_config on a x86 diskless system
			 * Emit verbose message only
			 */
			if (bam_verbose)
				bam_print(NFTW_FAIL, path, strerror(errno));
		}
	}
}

static void
savenew(char *root)
{
	char path[PATH_MAX];
	char path2[PATH_MAX];
	size_t sz;
	char *nstat;
	int fd, wrote, error;

	nstat = NULL;
	sz = 0;
	error = nvlist_pack(walk_arg.new_nvlp, &nstat, &sz,
	    NV_ENCODE_XDR, 0);
	if (error) {
		bam_error(PACK_FAIL, strerror(error));
		return;
	}

	(void) snprintf(path, sizeof (path), "%s%s", root, FILE_STAT_TMP);
	fd = open(path, O_RDWR|O_CREAT|O_TRUNC, FILE_STAT_MODE);
	if (fd == -1) {
		bam_error(OPEN_FAIL, path, strerror(errno));
		free(nstat);
		return;
	}
	wrote = write(fd, nstat, sz);
	if (wrote != sz) {
		bam_error(WRITE_FAIL, path, strerror(errno));
		(void) close(fd);
		free(nstat);
		return;
	}
	(void) close(fd);
	free(nstat);

	(void) snprintf(path2, sizeof (path2), "%s%s", root, FILE_STAT);
	if (rename(path, path2) != 0) {
		bam_error(RENAME_FAIL, path2, strerror(errno));
	}
}

static void
clear_walk_args(void)
{
	if (walk_arg.old_nvlp)
		nvlist_free(walk_arg.old_nvlp);
	if (walk_arg.new_nvlp)
		nvlist_free(walk_arg.new_nvlp);
	walk_arg.need_update = 0;
	walk_arg.old_nvlp = NULL;
	walk_arg.new_nvlp = NULL;
}

/*
 * Returns:
 *	0 - no update necessary
 *	1 - update required.
 *	BAM_ERROR (-1) - An error occurred
 *
 * Special handling for check (-n):
 * ================================
 * The check (-n) option produces parseable output.
 * To do this, we suppress all stdout messages unrelated
 * to out of sync files.
 * All stderr messages are still printed though.
 *
 */
static int
update_required(char *root)
{
	struct stat sb;
	char path[PATH_MAX];
	filelist_t flist;
	filelist_t *flistp = &flist;
	int need_update;

	flistp->head = flistp->tail = NULL;

	walk_arg.need_update = 0;

	/*
	 * Without consulting stat data, check if we need update
	 */
	check_flags_and_files(root);

	/*
	 * In certain deployment scenarios, filestat may not
	 * exist. Ignore it during boot-archive SMF check.
	 */
	if (bam_smf_check) {
		(void) snprintf(path, sizeof (path), "%s%s", root, FILE_STAT);
		if (stat(path, &sb) != 0)
			return (0);
	}

	/*
	 * consult stat data only if we haven't made a decision
	 * about update. If checking (-n) however, we always
	 * need stat data (since we want to compare old and new)
	 */
	if (!walk_arg.need_update || bam_check)
		getoldstat(root);

	/*
	 * Check if the archive contains files that are no longer
	 * present on the root filesystem.
	 */
	if (!walk_arg.need_update || bam_check)
		check4stale(root);

	/*
	 * read list of files
	 */
	if (read_list(root, flistp) != BAM_SUCCESS) {
		clear_walk_args();
		return (BAM_ERROR);
	}

	assert(flistp->head && flistp->tail);

	/*
	 * At this point either the update is required
	 * or the decision is pending. In either case
	 * we need to create new stat nvlist
	 */
	create_newstat();

	/*
	 * This walk does 2 things:
	 *  	- gets new stat data for every file
	 *	- (optional) compare old and new stat data
	 */
	walk_list(root, &flist);

	/* done with the file list */
	filelist_free(flistp);

	/*
	 * if we didn't succeed in  creating new stat data above
	 * just return result of update check so that archive is built.
	 */
	if (walk_arg.new_nvlp == NULL) {
		bam_error(NO_NEW_STAT);
		need_update = walk_arg.need_update;
		clear_walk_args();
		return (need_update ? 1 : 0);
	}


	/*
	 * If no update required, discard newstat
	 */
	if (!walk_arg.need_update) {
		clear_walk_args();
		return (0);
	}

	/*
	 * At this point we need an update - so save new stat data
	 * However, if only checking (-n), don't save new stat data.
	 */
	if (!bam_check)
		savenew(root);

	clear_walk_args();

	return (1);
}

static error_t
create_ramdisk(char *root)
{
	char *cmdline, path[PATH_MAX];
	size_t len;
	struct stat sb;

	/*
	 * Setup command args for create_ramdisk.ksh
	 */
	(void) snprintf(path, sizeof (path), "%s%s", root, CREATE_RAMDISK);
	if (stat(path, &sb) != 0) {
		bam_error(ARCH_EXEC_MISS, path, strerror(errno));
		return (BAM_ERROR);
	}

	len = strlen(path) + strlen(root) + 10;	/* room for space + -R */
	cmdline = s_calloc(1, len);

	if (strlen(root) > 1) {
		(void) snprintf(cmdline, len, "%s -R %s", path, root);
		/* chop off / at the end */
		cmdline[strlen(cmdline) - 1] = '\0';
	} else
		(void) snprintf(cmdline, len, "%s", path);

	if (exec_cmd(cmdline, NULL, 0) != 0) {
		bam_error(ARCHIVE_FAIL, cmdline);
		free(cmdline);
		return (BAM_ERROR);
	}
	free(cmdline);

	/*
	 * Verify that the archive has been created
	 */
	(void) snprintf(path, sizeof (path), "%s%s", root,
	    DIRECT_BOOT_ARCHIVE_32);
	if (stat(path, &sb) != 0) {
		bam_error(ARCHIVE_NOT_CREATED, path);
		return (BAM_ERROR);
	}
	if (bam_direct == BAM_DIRECT_DBOOT) {
		(void) snprintf(path, sizeof (path), "%s%s", root,
		    DIRECT_BOOT_ARCHIVE_64);
		if (stat(path, &sb) != 0) {
			bam_error(ARCHIVE_NOT_CREATED, path);
			return (BAM_ERROR);
		}
	}

	return (BAM_SUCCESS);
}

/*
 * Checks if target filesystem is on a ramdisk
 * 1 - is miniroot
 * 0 - is not
 * When in doubt assume it is not a ramdisk.
 */
static int
is_ramdisk(char *root)
{
	struct extmnttab mnt;
	FILE *fp;
	int found;
	char mntpt[PATH_MAX];
	char *cp;

	/*
	 * There are 3 situations where creating archive is
	 * of dubious value:
	 *	- create boot_archive on a lofi-mounted boot_archive
	 *	- create it on a ramdisk which is the root filesystem
	 *	- create it on a ramdisk mounted somewhere else
	 * The first is not easy to detect and checking for it is not
	 * worth it.
	 * The other two conditions are handled here
	 */

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, MNTTAB, strerror(errno));
		return (0);
	}

	resetmnttab(fp);

	/*
	 * Remove any trailing / from the mount point
	 */
	(void) strlcpy(mntpt, root, sizeof (mntpt));
	if (strcmp(root, "/") != 0) {
		cp = mntpt + strlen(mntpt) - 1;
		if (*cp == '/')
			*cp = '\0';
	}
	found = 0;
	while (getextmntent(fp, &mnt, sizeof (mnt)) == 0) {
		if (strcmp(mnt.mnt_mountp, mntpt) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		if (bam_verbose)
			bam_error(NOT_IN_MNTTAB, mntpt);
		(void) fclose(fp);
		return (0);
	}

	if (strstr(mnt.mnt_special, RAMDISK_SPECIAL) != NULL) {
		if (bam_verbose)
			bam_error(IS_RAMDISK, bam_root);
		(void) fclose(fp);
		return (1);
	}

	(void) fclose(fp);

	return (0);
}

static int
is_newboot(char *root)
{
	char path[PATH_MAX];
	struct stat sb;

	/*
	 * We can't boot without MULTI_BOOT
	 */
	(void) snprintf(path, sizeof (path), "%s%s", root, MULTI_BOOT);
	if (stat(path, &sb) == -1) {
		if (bam_verbose)
			bam_print(FILE_MISS, path);
		return (0);
	}

	/*
	 * We can't generate archive without GRUB_DIR
	 */
	(void) snprintf(path, sizeof (path), "%s%s", root, GRUB_DIR);
	if (stat(path, &sb) == -1) {
		if (bam_verbose)
			bam_print(DIR_MISS, path);
		return (0);
	}

	return (1);
}

static int
is_readonly(char *root)
{
	struct statvfs vfs;

	/*
	 * Check for RDONLY filesystem
	 * When in doubt assume it is not readonly
	 */
	if (statvfs(root, &vfs) != 0) {
		if (bam_verbose)
			bam_error(STATVFS_FAIL, root, strerror(errno));
		return (0);
	}

	if (vfs.f_flag & ST_RDONLY) {
		return (1);
	}

	return (0);
}

static error_t
update_archive(char *root, char *opt)
{
	error_t ret;

	assert(root);
	assert(opt == NULL);

	/*
	 * root must belong to a GRUB boot OS,
	 * don't care on sparc except for diskless clients
	 */
	if (!is_newboot(root)) {
		/*
		 * Emit message only if not in context of update_all.
		 * If in update_all, emit only if verbose flag is set.
		 */
		if (!bam_update_all || bam_verbose)
			bam_print(NOT_GRUB_BOOT, root);
		return (BAM_SUCCESS);
	}

	/*
	 * If smf check is requested when / is writable (can happen
	 * on first reboot following an upgrade because service
	 * dependency is messed up), skip the check.
	 */
	if (bam_smf_check && !bam_root_readonly)
		return (BAM_SUCCESS);

	/*
	 * root must be writable. This check applies to alternate
	 * root (-R option); bam_root_readonly applies to '/' only.
	 * Note: statvfs() does not always report the truth
	 */
	if (!bam_smf_check && !bam_check && is_readonly(root)) {
		if (bam_verbose)
			bam_print(RDONLY_FS, root);
		return (BAM_SUCCESS);
	}

	/*
	 * Don't generate archive on ramdisk
	 */
	if (is_ramdisk(root)) {
		if (bam_verbose)
			bam_print(SKIP_RAMDISK);
		return (BAM_SUCCESS);
	}

	/*
	 * Now check if updated is really needed
	 */
	ret = update_required(root);

	/*
	 * The check command (-n) is *not* a dry run
	 * It only checks if the archive is in sync.
	 */
	if (bam_check) {
		bam_exit((ret != 0) ? 1 : 0);
	}

	if (ret == 1) {
		/* create the ramdisk */
		ret = create_ramdisk(root);
	}
	return (ret);
}

static void
update_fdisk(void)
{
	struct stat sb;
	char cmd[PATH_MAX];
	int ret1, ret2;

	assert(stat(GRUB_fdisk, &sb) == 0);
	assert(stat(GRUB_fdisk_target, &sb) == 0);

	(void) snprintf(cmd, sizeof (cmd), "/sbin/fdisk -F %s `/bin/cat %s`",
	    GRUB_fdisk, GRUB_fdisk_target);

	bam_print(UPDATING_FDISK);
	if (exec_cmd(cmd, NULL, 0) != 0) {
		bam_error(FDISK_UPDATE_FAILED);
	}

	/*
	 * We are done, remove the files.
	 */
	ret1 = unlink(GRUB_fdisk);
	ret2 = unlink(GRUB_fdisk_target);
	if (ret1 != 0 || ret2 != 0) {
		bam_error(FILE_REMOVE_FAILED, GRUB_fdisk, GRUB_fdisk_target);
	}
}

static void
restore_grub_slice(void)
{
	struct stat sb;
	char *mntpt, *physlice;
	int mnted;	/* set if we did a mount */
	char menupath[PATH_MAX], cmd[PATH_MAX];

	if (stat(GRUB_slice, &sb) != 0) {
		bam_error(MISSING_SLICE_FILE, GRUB_slice, strerror(errno));
		return;
	}

	/*
	 * If we are doing an luactivate, don't attempt to restore GRUB or else
	 * we may not be able to get to DCA boot environments. Let luactivate
	 * handle GRUB/DCA installation
	 */
	if (stat(LU_ACTIVATE_FILE, &sb) == 0) {
		return;
	}

	mnted = 0;
	physlice = NULL;
	mntpt = mount_grub_slice(&mnted, &physlice, NULL, NULL);
	if (mntpt == NULL) {
		bam_error(CANNOT_RESTORE_GRUB_SLICE);
		return;
	}

	(void) snprintf(menupath, sizeof (menupath), "%s%s", mntpt, GRUB_MENU);
	if (stat(menupath, &sb) == 0) {
		umount_grub_slice(mnted, mntpt, physlice, NULL, NULL);
		return;
	}

	/*
	 * The menu is missing - we need to do a restore
	 */
	bam_print(RESTORING_GRUB);

	(void) snprintf(cmd, sizeof (cmd), "%s %s %s %s",
	    INSTALLGRUB, STAGE1, STAGE2, physlice);

	if (exec_cmd(cmd, NULL, 0) != 0) {
		bam_error(RESTORE_GRUB_FAILED);
		umount_grub_slice(mnted, mntpt, physlice, NULL, NULL);
		return;
	}

	if (stat(GRUB_backup_menu, &sb) != 0) {
		bam_error(MISSING_BACKUP_MENU,
		    GRUB_backup_menu, strerror(errno));
		umount_grub_slice(mnted, mntpt, physlice, NULL, NULL);
		return;
	}

	(void) snprintf(cmd, sizeof (cmd), "/bin/cp %s %s",
	    GRUB_backup_menu, menupath);

	if (exec_cmd(cmd, NULL, 0) != 0) {
		bam_error(RESTORE_MENU_FAILED, menupath);
		umount_grub_slice(mnted, mntpt, physlice, NULL, NULL);
		return;
	}

	/* Success */
	umount_grub_slice(mnted, mntpt, physlice, NULL, NULL);
}

static error_t
update_all(char *root, char *opt)
{
	struct extmnttab mnt;
	struct stat sb;
	FILE *fp;
	char multibt[PATH_MAX];
	error_t ret = BAM_SUCCESS;
	int ret1, ret2;

	assert(root);
	assert(opt == NULL);

	if (bam_rootlen != 1 || *root != '/') {
		elide_trailing_slash(root, multibt, sizeof (multibt));
		bam_error(ALT_ROOT_INVALID, multibt);
		return (BAM_ERROR);
	}

	/*
	 * Check to see if we are in the midst of safemode patching
	 * If so skip building the archive for /. Instead build it
	 * against the latest bits obtained by creating a fresh lofs
	 * mount of root.
	 */
	if (stat(LOFS_PATCH_FILE, &sb) == 0)  {
		if (mkdir(LOFS_PATCH_MNT, 0755) == -1 &&
		    errno != EEXIST) {
			bam_error(MKDIR_FAILED, "%s", LOFS_PATCH_MNT,
			    strerror(errno));
			ret = BAM_ERROR;
			goto out;
		}
		(void) snprintf(multibt, sizeof (multibt),
		    "/sbin/mount -F lofs -o nosub /  %s", LOFS_PATCH_MNT);
		if (exec_cmd(multibt, NULL, 0) != 0) {
			bam_error(MOUNT_FAILED, LOFS_PATCH_MNT, "lofs");
			ret = BAM_ERROR;
		}
		if (ret != BAM_ERROR) {
			(void) snprintf(rootbuf, sizeof (rootbuf), "%s/",
			    LOFS_PATCH_MNT);
			bam_rootlen = strlen(rootbuf);
			if (update_archive(rootbuf, opt) != BAM_SUCCESS)
				ret = BAM_ERROR;
			/*
			 * unmount the lofs mount since there could be
			 * multiple invocations of bootadm -a update_all
			 */
			(void) snprintf(multibt, sizeof (multibt),
			    "/sbin/umount %s", LOFS_PATCH_MNT);
			if (exec_cmd(multibt, NULL, 0) != 0) {
				bam_error(UMOUNT_FAILED, LOFS_PATCH_MNT);
				ret = BAM_ERROR;
			}
		}
	} else {
		/*
		 * First update archive for current root
		 */
		if (update_archive(root, opt) != BAM_SUCCESS)
			ret = BAM_ERROR;
	}

	if (ret == BAM_ERROR)
		goto out;

	/*
	 * Now walk the mount table, performing archive update
	 * for all mounted Newboot root filesystems
	 */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, MNTTAB, strerror(errno));
		ret = BAM_ERROR;
		goto out;
	}

	resetmnttab(fp);

	while (getextmntent(fp, &mnt, sizeof (mnt)) == 0) {
		if (mnt.mnt_special == NULL)
			continue;
		if (strncmp(mnt.mnt_special, "/dev/", strlen("/dev/")) != 0)
			continue;
		if (strcmp(mnt.mnt_mountp, "/") == 0)
			continue;

		(void) snprintf(multibt, sizeof (multibt), "%s%s",
		    mnt.mnt_mountp, MULTI_BOOT);

		if (stat(multibt, &sb) == -1)
			continue;

		/*
		 * We put a trailing slash to be consistent with root = "/"
		 * case, such that we don't have to print // in some cases.
		 */
		(void) snprintf(rootbuf, sizeof (rootbuf), "%s/",
		    mnt.mnt_mountp);
		bam_rootlen = strlen(rootbuf);

		/*
		 * It's possible that other mounts may be an alternate boot
		 * architecture, so check it again.
		 */
		if ((dboot_or_multiboot(rootbuf) != BAM_SUCCESS) ||
		    (update_archive(rootbuf, opt) != BAM_SUCCESS))
			ret = BAM_ERROR;
	}

	(void) fclose(fp);

out:
	if (stat(GRUB_slice, &sb) == 0) {
		restore_grub_slice();
	}

	/*
	 * Update fdisk table as we go down. Updating it when
	 * the system is running will confuse biosdev.
	 */
	ret1 = stat(GRUB_fdisk, &sb);
	ret2 = stat(GRUB_fdisk_target, &sb);
	if ((ret1 == 0) && (ret2 == 0)) {
		update_fdisk();
	} else if ((ret1 == 0) ^ (ret2 == 0)) {
		/*
		 * It is an error for one file to be
		 * present and the other absent.
		 * It is normal for both files to be
		 * absent - it indicates that no fdisk
		 * update is required.
		 */
		bam_error(MISSING_FDISK_FILE,
		    ret1 ? GRUB_fdisk : GRUB_fdisk_target);
		ret = BAM_ERROR;
	}

	return (ret);
}

static void
append_line(menu_t *mp, line_t *lp)
{
	if (mp->start == NULL) {
		mp->start = lp;
	} else {
		mp->end->next = lp;
		lp->prev = mp->end;
	}
	mp->end = lp;
}

static void
unlink_line(menu_t *mp, line_t *lp)
{
	/* unlink from list */
	if (lp->prev)
		lp->prev->next = lp->next;
	else
		mp->start = lp->next;
	if (lp->next)
		lp->next->prev = lp->prev;
	else
		mp->end = lp->prev;
}

static entry_t *
boot_entry_new(menu_t *mp, line_t *start, line_t *end)
{
	entry_t *ent, *prev;

	ent = s_calloc(1, sizeof (entry_t));
	ent->start = start;
	ent->end = end;

	if (mp->entries == NULL) {
		mp->entries = ent;
		return (ent);
	}

	prev = mp->entries;
	while (prev->next)
		prev = prev-> next;
	prev->next = ent;
	ent->prev = prev;
	return (ent);
}

static void
boot_entry_addline(entry_t *ent, line_t *lp)
{
	if (ent)
		ent->end = lp;
}

/*
 * Check whether cmd matches the one indexed by which, and whether arg matches
 * str.  which must be either KERNEL_CMD or MODULE_CMD, and a match to the
 * respective *_DOLLAR_CMD is also acceptable.  The arg is searched using
 * strstr(), so it can be a partial match.
 */
static int
check_cmd(const char *cmd, const int which, const char *arg, const char *str)
{
	if ((strcmp(cmd, menu_cmds[which]) != 0) &&
	    (strcmp(cmd, menu_cmds[which + 1]) != 0)) {
		return (0);
	}
	return (strstr(arg, str) != NULL);
}

/*
 * A line in menu.lst looks like
 * [ ]*<cmd>[ \t=]*<arg>*
 */
static void
line_parser(menu_t *mp, char *str, int *lineNum, int *entryNum)
{
	/*
	 * save state across calls. This is so that
	 * header gets the right entry# after title has
	 * been processed
	 */
	static line_t *prev = NULL;
	static entry_t *curr_ent = NULL;
	static int in_liveupgrade = 0;

	line_t	*lp;
	char *cmd, *sep, *arg;
	char save, *cp, *line;
	menu_flag_t flag = BAM_INVALID;

	if (str == NULL) {
		return;
	}

	/*
	 * First save a copy of the entire line.
	 * We use this later to set the line field.
	 */
	line = s_strdup(str);

	/* Eat up leading whitespace */
	while (*str == ' ' || *str == '\t')
		str++;

	if (*str == '#') {		/* comment */
		cmd = s_strdup("#");
		sep = NULL;
		arg = s_strdup(str + 1);
		flag = BAM_COMMENT;
		if (strstr(arg, BAM_LU_HDR) != NULL) {
			in_liveupgrade = 1;
		} else if (strstr(arg, BAM_LU_FTR) != NULL) {
			in_liveupgrade = 0;
		}
	} else if (*str == '\0') {	/* blank line */
		cmd = sep = arg = NULL;
		flag = BAM_EMPTY;
	} else {
		/*
		 * '=' is not a documented separator in grub syntax.
		 * However various development bits use '=' as a
		 * separator. In addition, external users also
		 * use = as a separator. So we will allow that usage.
		 */
		cp = str;
		while (*str != ' ' && *str != '\t' && *str != '=') {
			if (*str == '\0') {
				cmd = s_strdup(cp);
				sep = arg = NULL;
				break;
			}
			str++;
		}

		if (*str != '\0') {
			save = *str;
			*str = '\0';
			cmd = s_strdup(cp);
			*str = save;

			str++;
			save = *str;
			*str = '\0';
			sep = s_strdup(str - 1);
			*str = save;

			while (*str == ' ' || *str == '\t')
				str++;
			if (*str == '\0')
				arg = NULL;
			else
				arg = s_strdup(str);
		}
	}

	lp = s_calloc(1, sizeof (line_t));

	lp->cmd = cmd;
	lp->sep = sep;
	lp->arg = arg;
	lp->line = line;
	lp->lineNum = ++(*lineNum);
	if (cmd && strcmp(cmd, menu_cmds[TITLE_CMD]) == 0) {
		lp->entryNum = ++(*entryNum);
		lp->flags = BAM_TITLE;
		if (prev && prev->flags == BAM_COMMENT &&
		    prev->arg && strcmp(prev->arg, BAM_BOOTADM_HDR) == 0) {
			prev->entryNum = lp->entryNum;
			curr_ent = boot_entry_new(mp, prev, lp);
			curr_ent->flags = BAM_ENTRY_BOOTADM;
		} else {
			curr_ent = boot_entry_new(mp, lp, lp);
			if (in_liveupgrade) {
				curr_ent->flags = BAM_ENTRY_LU;
			}
		}
		curr_ent->entryNum = *entryNum;
	} else if (flag != BAM_INVALID) {
		/*
		 * For header comments, the entry# is "fixed up"
		 * by the subsequent title
		 */
		lp->entryNum = *entryNum;
		lp->flags = flag;
	} else {
		lp->entryNum = *entryNum;

		if (*entryNum == ENTRY_INIT) {
			lp->flags = BAM_GLOBAL;
		} else {
			lp->flags = BAM_ENTRY;

			if (cmd && arg) {
				/*
				 * We only compare for the length of "module"
				 * so that "module$" will also match.
				 */
				if (check_cmd(cmd, MODULE_CMD, arg, MINIROOT))
					curr_ent->flags |= BAM_ENTRY_MINIROOT;
				else if (check_cmd(cmd, KERNEL_CMD, arg,
				    "xen.gz"))
					curr_ent->flags |= BAM_ENTRY_HV;
				else if (strcmp(cmd, menu_cmds[ROOT_CMD]) == 0)
					curr_ent->flags |= BAM_ENTRY_ROOT;
				else if (strcmp(cmd,
				    menu_cmds[CHAINLOADER_CMD]) == 0)
					curr_ent->flags |=
					    BAM_ENTRY_CHAINLOADER;
			}
		}
	}

	/* record default, old default, and entry line ranges */
	if (lp->flags == BAM_GLOBAL &&
	    strcmp(lp->cmd, menu_cmds[DEFAULT_CMD]) == 0) {
		mp->curdefault = lp;
	} else if (lp->flags == BAM_COMMENT &&
	    strncmp(lp->arg, BAM_OLDDEF, strlen(BAM_OLDDEF)) == 0) {
		mp->olddefault = lp;
	} else if (lp->flags == BAM_COMMENT &&
	    strncmp(lp->arg, BAM_OLD_RC_DEF, strlen(BAM_OLD_RC_DEF)) == 0) {
		mp->old_rc_default = lp;
	} else if (lp->flags == BAM_ENTRY ||
	    (lp->flags == BAM_COMMENT &&
	    strcmp(lp->arg, BAM_BOOTADM_FTR) == 0)) {
		boot_entry_addline(curr_ent, lp);
	}
	append_line(mp, lp);

	prev = lp;
}

static void
update_numbering(menu_t *mp)
{
	int lineNum;
	int entryNum;
	int old_default_value;
	line_t *lp, *prev, *default_lp, *default_entry;
	char buf[PATH_MAX];

	if (mp->start == NULL) {
		return;
	}

	lineNum = LINE_INIT;
	entryNum = ENTRY_INIT;
	old_default_value = ENTRY_INIT;
	lp = default_lp = default_entry = NULL;

	prev = NULL;
	for (lp = mp->start; lp; prev = lp, lp = lp->next) {
		lp->lineNum = ++lineNum;

		/*
		 * Get the value of the default command
		 */
		if (lp->entryNum == ENTRY_INIT && lp->cmd &&
		    strcmp(lp->cmd, menu_cmds[DEFAULT_CMD]) == 0 &&
		    lp->arg) {
			old_default_value = atoi(lp->arg);
			default_lp = lp;
		}

		/*
		 * If not boot entry, nothing else to fix for this
		 * entry
		 */
		if (lp->entryNum == ENTRY_INIT)
			continue;

		/*
		 * Record the position of the default entry.
		 * The following works because global
		 * commands like default and timeout should precede
		 * actual boot entries, so old_default_value
		 * is already known (or default cmd is missing).
		 */
		if (default_entry == NULL &&
		    old_default_value != ENTRY_INIT &&
		    lp->entryNum == old_default_value) {
			default_entry = lp;
		}

		/*
		 * Now fixup the entry number
		 */
		if (lp->cmd && strcmp(lp->cmd, menu_cmds[TITLE_CMD]) == 0) {
			lp->entryNum = ++entryNum;
			/* fixup the bootadm header */
			if (prev && prev->flags == BAM_COMMENT &&
			    prev->arg &&
			    strcmp(prev->arg, BAM_BOOTADM_HDR) == 0) {
				prev->entryNum = lp->entryNum;
			}
		} else {
			lp->entryNum = entryNum;
		}
	}

	/*
	 * No default command in menu, simply return
	 */
	if (default_lp == NULL) {
		return;
	}

	free(default_lp->arg);
	free(default_lp->line);

	if (default_entry == NULL) {
		default_lp->arg = s_strdup("0");
	} else {
		(void) snprintf(buf, sizeof (buf), "%d",
		    default_entry->entryNum);
		default_lp->arg = s_strdup(buf);
	}

	/*
	 * The following is required since only the line field gets
	 * written back to menu.lst
	 */
	(void) snprintf(buf, sizeof (buf), "%s%s%s",
	    menu_cmds[DEFAULT_CMD], menu_cmds[SEP_CMD], default_lp->arg);
	default_lp->line = s_strdup(buf);
}


static menu_t *
menu_read(char *menu_path)
{
	FILE *fp;
	char buf[BAM_MAXLINE], *cp;
	menu_t *mp;
	int line, entry, len, n;

	mp = s_calloc(1, sizeof (menu_t));

	fp = fopen(menu_path, "r");
	if (fp == NULL) { /* Let the caller handle this error */
		return (mp);
	}


	/* Note: GRUB boot entry number starts with 0 */
	line = LINE_INIT;
	entry = ENTRY_INIT;
	cp = buf;
	len = sizeof (buf);
	while (s_fgets(cp, len, fp) != NULL) {
		n = strlen(cp);
		if (cp[n - 1] == '\\') {
			len -= n - 1;
			assert(len >= 2);
			cp += n - 1;
			continue;
		}
		line_parser(mp, buf, &line, &entry);
		cp = buf;
		len = sizeof (buf);
	}

	if (fclose(fp) == EOF) {
		bam_error(CLOSE_FAIL, menu_path, strerror(errno));
	}

	return (mp);
}

static error_t
selector(menu_t *mp, char *opt, int *entry, char **title)
{
	char *eq;
	char *opt_dup;
	int entryNum;

	assert(mp);
	assert(mp->start);
	assert(opt);

	opt_dup = s_strdup(opt);

	if (entry)
		*entry = ENTRY_INIT;
	if (title)
		*title = NULL;

	eq = strchr(opt_dup, '=');
	if (eq == NULL) {
		bam_error(INVALID_OPT, opt);
		free(opt_dup);
		return (BAM_ERROR);
	}

	*eq = '\0';
	if (entry && strcmp(opt_dup, OPT_ENTRY_NUM) == 0) {
		assert(mp->end);
		entryNum = s_strtol(eq + 1);
		if (entryNum < 0 || entryNum > mp->end->entryNum) {
			bam_error(INVALID_ENTRY, eq + 1);
			free(opt_dup);
			return (BAM_ERROR);
		}
		*entry = entryNum;
	} else if (title && strcmp(opt_dup, menu_cmds[TITLE_CMD]) == 0) {
		*title = opt + (eq - opt_dup) + 1;
	} else {
		bam_error(INVALID_OPT, opt);
		free(opt_dup);
		return (BAM_ERROR);
	}

	free(opt_dup);
	return (BAM_SUCCESS);
}

/*
 * If invoked with no titles/entries (opt == NULL)
 * only title lines in file are printed.
 *
 * If invoked with a title or entry #, all
 * lines in *every* matching entry are listed
 */
static error_t
list_entry(menu_t *mp, char *menu_path, char *opt)
{
	line_t *lp;
	int entry = ENTRY_INIT;
	int found;
	char *title = NULL;

	assert(mp);
	assert(menu_path);

	if (mp->start == NULL) {
		bam_error(NO_MENU, menu_path);
		return (BAM_ERROR);
	}

	if (opt != NULL) {
		if (selector(mp, opt, &entry, &title) != BAM_SUCCESS) {
			return (BAM_ERROR);
		}
		assert((entry != ENTRY_INIT) ^ (title != NULL));
	} else {
		(void) read_globals(mp, menu_path, menu_cmds[DEFAULT_CMD], 0);
		(void) read_globals(mp, menu_path, menu_cmds[TIMEOUT_CMD], 0);
	}

	found = 0;
	for (lp = mp->start; lp; lp = lp->next) {
		if (lp->flags == BAM_COMMENT || lp->flags == BAM_EMPTY)
			continue;
		if (opt == NULL && lp->flags == BAM_TITLE) {
			bam_print(PRINT_TITLE, lp->entryNum,
			    lp->arg);
			found = 1;
			continue;
		}
		if (entry != ENTRY_INIT && lp->entryNum == entry) {
			bam_print(PRINT, lp->line);
			found = 1;
			continue;
		}

		/*
		 * We set the entry value here so that all lines
		 * in entry get printed. If we subsequently match
		 * title in other entries, all lines in those
		 * entries get printed as well.
		 */
		if (title && lp->flags == BAM_TITLE && lp->arg &&
		    strncmp(title, lp->arg, strlen(title)) == 0) {
			bam_print(PRINT, lp->line);
			entry = lp->entryNum;
			found = 1;
			continue;
		}
	}

	if (!found) {
		bam_error(NO_MATCH_ENTRY);
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

int
add_boot_entry(menu_t *mp,
	char *title,
	char *root,
	char *kernel,
	char *mod_kernel,
	char *module)
{
	int lineNum, entryNum;
	char linebuf[BAM_MAXLINE];
	menu_cmd_t k_cmd, m_cmd;

	assert(mp);

	if (title == NULL) {
		title = "Solaris";	/* default to Solaris */
	}
	if (kernel == NULL) {
		bam_error(SUBOPT_MISS, menu_cmds[KERNEL_CMD]);
		return (BAM_ERROR);
	}
	if (module == NULL) {
		if (bam_direct != BAM_DIRECT_DBOOT) {
			bam_error(SUBOPT_MISS, menu_cmds[MODULE_CMD]);
			return (BAM_ERROR);
		}

		/* Figure the commands out from the kernel line */
		if (strstr(kernel, "$ISADIR") != NULL) {
			module = DIRECT_BOOT_ARCHIVE;
			k_cmd = KERNEL_DOLLAR_CMD;
			m_cmd = MODULE_DOLLAR_CMD;
		} else if (strstr(kernel, "amd64") != NULL) {
			module = DIRECT_BOOT_ARCHIVE_64;
			k_cmd = KERNEL_CMD;
			m_cmd = MODULE_CMD;
		} else {
			module = DIRECT_BOOT_ARCHIVE_32;
			k_cmd = KERNEL_CMD;
			m_cmd = MODULE_CMD;
		}
	} else if ((bam_direct == BAM_DIRECT_DBOOT) &&
	    (strstr(kernel, "$ISADIR") != NULL)) {
		/*
		 * If it's a non-failsafe dboot kernel, use the "kernel$"
		 * command.  Otherwise, use "kernel".
		 */
		k_cmd = KERNEL_DOLLAR_CMD;
		m_cmd = MODULE_DOLLAR_CMD;
	} else {
		k_cmd = KERNEL_CMD;
		m_cmd = MODULE_CMD;
	}

	if (mp->start) {
		lineNum = mp->end->lineNum;
		entryNum = mp->end->entryNum;
	} else {
		lineNum = LINE_INIT;
		entryNum = ENTRY_INIT;
	}

	/*
	 * No separator for comment (HDR/FTR) commands
	 * The syntax for comments is #<comment>
	 */
	(void) snprintf(linebuf, sizeof (linebuf), "%s%s",
	    menu_cmds[COMMENT_CMD], BAM_BOOTADM_HDR);
	line_parser(mp, linebuf, &lineNum, &entryNum);

	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[TITLE_CMD], menu_cmds[SEP_CMD], title);
	line_parser(mp, linebuf, &lineNum, &entryNum);

	if (root) {
		(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
		    menu_cmds[ROOT_CMD], menu_cmds[SEP_CMD], root);
		line_parser(mp, linebuf, &lineNum, &entryNum);
	}

	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[k_cmd], menu_cmds[SEP_CMD], kernel);
	line_parser(mp, linebuf, &lineNum, &entryNum);

	if (mod_kernel != NULL) {
		(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
		    menu_cmds[m_cmd], menu_cmds[SEP_CMD], mod_kernel);
		line_parser(mp, linebuf, &lineNum, &entryNum);
	}

	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[m_cmd], menu_cmds[SEP_CMD], module);
	line_parser(mp, linebuf, &lineNum, &entryNum);

	(void) snprintf(linebuf, sizeof (linebuf), "%s%s",
	    menu_cmds[COMMENT_CMD], BAM_BOOTADM_FTR);
	line_parser(mp, linebuf, &lineNum, &entryNum);

	return (entryNum);
}

static error_t
do_delete(menu_t *mp, int entryNum)
{
	line_t *lp, *freed;
	entry_t *ent, *tmp;
	int deleted;

	assert(entryNum != ENTRY_INIT);

	ent = mp->entries;
	while (ent) {
		lp = ent->start;
		/* check entry number and make sure it's a bootadm entry */
		if (lp->flags != BAM_COMMENT ||
		    strcmp(lp->arg, BAM_BOOTADM_HDR) != 0 ||
		    (entryNum != ALL_ENTRIES && lp->entryNum != entryNum)) {
			ent = ent->next;
			continue;
		}

		/* free the entry content */
		do {
			freed = lp;
			lp = lp->next;	/* prev stays the same */
			unlink_line(mp, freed);
			line_free(freed);
		} while (freed != ent->end);

		/* free the entry_t structure */
		tmp = ent;
		ent = ent->next;
		if (tmp->prev)
			tmp->prev->next = ent;
		else
			mp->entries = ent;
		if (ent)
			ent->prev = tmp->prev;
		deleted = 1;
	}

	if (!deleted && entryNum != ALL_ENTRIES) {
		bam_error(NO_BOOTADM_MATCH);
		return (BAM_ERROR);
	}

	/*
	 * Now that we have deleted an entry, update
	 * the entry numbering and the default cmd.
	 */
	update_numbering(mp);

	return (BAM_SUCCESS);
}

static error_t
delete_all_entries(menu_t *mp, char *menu_path, char *opt)
{
	assert(mp);
	assert(opt == NULL);

	if (mp->start == NULL) {
		bam_print(EMPTY_FILE, menu_path);
		return (BAM_SUCCESS);
	}

	if (do_delete(mp, ALL_ENTRIES) != BAM_SUCCESS) {
		return (BAM_ERROR);
	}

	return (BAM_WRITE);
}

static FILE *
open_diskmap(char *root)
{
	FILE *fp;
	char cmd[PATH_MAX];

	/* make sure we have a map file */
	fp = fopen(GRUBDISK_MAP, "r");
	if (fp == NULL) {
		(void) snprintf(cmd, sizeof (cmd),
		    "%s%s > /dev/null", root, CREATE_DISKMAP);
		(void) system(cmd);
		fp = fopen(GRUBDISK_MAP, "r");
	}
	return (fp);
}

#define	SECTOR_SIZE	512

static int
get_partition(char *device)
{
	int i, fd, is_pcfs, partno = -1;
	struct mboot *mboot;
	char boot_sect[SECTOR_SIZE];
	char *wholedisk, *slice;

	/* form whole disk (p0) */
	slice = device + strlen(device) - 2;
	is_pcfs = (*slice != 's');
	if (!is_pcfs)
		*slice = '\0';
	wholedisk = s_calloc(1, strlen(device) + 3);
	(void) snprintf(wholedisk, strlen(device) + 3, "%sp0", device);
	if (!is_pcfs)
		*slice = 's';

	/* read boot sector */
	fd = open(wholedisk, O_RDONLY);
	free(wholedisk);
	if (fd == -1 || read(fd, boot_sect, SECTOR_SIZE) != SECTOR_SIZE) {
		return (partno);
	}
	(void) close(fd);

	/* parse fdisk table */
	mboot = (struct mboot *)((void *)boot_sect);
	for (i = 0; i < FD_NUMPART; i++) {
		struct ipart *part =
		    (struct ipart *)(uintptr_t)mboot->parts + i;
		if (is_pcfs) {	/* looking for solaris boot part */
			if (part->systid == 0xbe) {
				partno = i;
				break;
			}
		} else {	/* look for solaris partition, old and new */
			if (part->systid == SUNIXOS ||
			    part->systid == SUNIXOS2) {
				partno = i;
				break;
			}
		}
	}
	return (partno);
}

static char *
get_grubdisk(char *rootdev, FILE *fp, int on_bootdev)
{
	char *grubdisk;	/* (hd#,#,#) */
	char *slice;
	char *grubhd;
	int fdiskpart;
	int found = 0;
	char *devname, *ctdname = strstr(rootdev, "dsk/");
	char linebuf[PATH_MAX];

	if (ctdname == NULL)
		return (NULL);

	ctdname += strlen("dsk/");
	slice = strrchr(ctdname, 's');
	if (slice)
		*slice = '\0';

	rewind(fp);
	while (s_fgets(linebuf, sizeof (linebuf), fp) != NULL) {
		grubhd = strtok(linebuf, " \t\n");
		if (grubhd)
			devname = strtok(NULL, " \t\n");
		else
			devname = NULL;
		if (devname && strcmp(devname, ctdname) == 0) {
			found = 1;
			break;
		}
	}

	if (slice)
		*slice = 's';

	if (found == 0) {
		if (bam_verbose)
			bam_print(DISKMAP_FAIL_NONFATAL, rootdev);
		grubhd = "0";	/* assume disk 0 if can't match */
	}

	fdiskpart = get_partition(rootdev);
	if (fdiskpart == -1)
		return (NULL);

	grubdisk = s_calloc(1, 10);
	if (slice) {
		(void) snprintf(grubdisk, 10, "(hd%s,%d,%c)",
		    grubhd, fdiskpart, slice[1] + 'a' - '0');
	} else
		(void) snprintf(grubdisk, 10, "(hd%s,%d)",
		    grubhd, fdiskpart);

	/* if root not on bootdev, change GRUB disk to 0 */
	if (!on_bootdev)
		grubdisk[3] = '0';
	return (grubdisk);
}

static char *
get_title(char *rootdir)
{
	static char title[80];	/* from /etc/release */
	char *cp = NULL, release[PATH_MAX];
	FILE *fp;

	/* open the /etc/release file */
	(void) snprintf(release, sizeof (release), "%s/etc/release", rootdir);

	fp = fopen(release, "r");
	if (fp == NULL)
		return (NULL);

	while (s_fgets(title, sizeof (title), fp) != NULL) {
		cp = strstr(title, "Solaris");
		if (cp)
			break;
	}
	(void) fclose(fp);
	return (cp == NULL ? "Solaris" : cp);
}

char *
get_special(char *mountp)
{
	FILE *mntfp;
	struct mnttab mp = {0}, mpref = {0};

	mntfp = fopen(MNTTAB, "r");
	if (mntfp == NULL) {
		return (0);
	}

	if (*mountp == '\0')
		mpref.mnt_mountp = "/";
	else
		mpref.mnt_mountp = mountp;
	if (getmntany(mntfp, &mp, &mpref) != 0) {
		(void) fclose(mntfp);
		return (NULL);
	}
	(void) fclose(mntfp);

	return (s_strdup(mp.mnt_special));
}

char *
os_to_grubdisk(char *osdisk, int on_bootdev)
{
	FILE *fp;
	char *grubdisk;

	/* translate /dev/dsk name to grub disk name */
	fp = open_diskmap("");
	if (fp == NULL) {
		bam_error(DISKMAP_FAIL, osdisk);
		return (NULL);
	}
	grubdisk = get_grubdisk(osdisk, fp, on_bootdev);
	(void) fclose(fp);
	return (grubdisk);
}

/*
 * Check if root is on the boot device
 * Return 0 (false) on error
 */
static int
menu_on_bootdev(char *menu_root, FILE *fp)
{
	int ret;
	char *grubhd, *bootp, *special;

	special = get_special(menu_root);
	if (special == NULL)
		return (0);
	bootp = strstr(special, "p0:boot");
	if (bootp)
		*bootp = '\0';
	grubhd = get_grubdisk(special, fp, 1);
	free(special);

	if (grubhd == NULL)
		return (0);
	ret = grubhd[3] == '0';
	free(grubhd);
	return (ret);
}

/*
 * look for matching bootadm entry with specified parameters
 * Here are the rules (based on existing usage):
 * - If title is specified, match on title only
 * - Else, match on kernel, grubdisk and module.  Note that, if root_opt is
 *   non-zero, the absence of root line is considered a match.
 */
static entry_t *
find_boot_entry(menu_t *mp, char *title, char *kernel, char *root,
    char *module, int root_opt, int *entry_num)
{
	int i;
	line_t *lp;
	entry_t *ent;

	/* find matching entry */
	for (i = 0, ent = mp->entries; ent; i++, ent = ent->next) {
		lp = ent->start;

		/* first line of entry must be bootadm comment */
		lp = ent->start;
		if (lp->flags != BAM_COMMENT ||
		    strcmp(lp->arg, BAM_BOOTADM_HDR) != 0) {
			continue;
		}

		/* advance to title line */
		lp = lp->next;
		if (title) {
			if (lp->flags == BAM_TITLE && lp->arg &&
			    strcmp(lp->arg, title) == 0)
				break;
			continue;	/* check title only */
		}

		lp = lp->next;	/* advance to root line */
		if (lp == NULL) {
			continue;
		} else if (strcmp(lp->cmd, menu_cmds[ROOT_CMD]) == 0) {
			/* root command found, match grub disk */
			if (strcmp(lp->arg, root) != 0) {
				continue;
			}
			lp = lp->next;	/* advance to kernel line */
		} else {
			/* no root command, see if root is optional */
			if (root_opt == 0) {
				continue;
			}
		}

		if (lp == NULL || lp->next == NULL) {
			continue;
		}

		if (kernel &&
		    (!check_cmd(lp->cmd, KERNEL_CMD, lp->arg, kernel))) {
			continue;
		}

		/*
		 * Check for matching module entry (failsafe or normal).
		 * If it fails to match, we go around the loop again.
		 * For xpv entries, there are two module lines, so we
		 * do the check twice.
		 */
		lp = lp->next;	/* advance to module line */
		if (check_cmd(lp->cmd, MODULE_CMD, lp->arg, module) ||
		    (((lp = lp->next) != NULL) &&
		    check_cmd(lp->cmd, MODULE_CMD, lp->arg, module))) {
			/* match found */
			break;
		}
	}

	if (entry_num && ent) {
		*entry_num = i;
	}
	return (ent);
}

static int
update_boot_entry(menu_t *mp, char *title, char *root, char *kernel,
    char *mod_kernel, char *module, int root_opt)
{
	int i, change_kernel = 0;
	entry_t *ent;
	line_t *lp;
	char linebuf[BAM_MAXLINE];

	/* note: don't match on title, it's updated on upgrade */
	ent = find_boot_entry(mp, NULL, kernel, root, module, root_opt, &i);
	if ((ent == NULL) && (bam_direct == BAM_DIRECT_DBOOT)) {
		/*
		 * We may be upgrading a kernel from multiboot to
		 * directboot.  Look for a multiboot entry.
		 */
		ent = find_boot_entry(mp, NULL, "multiboot", root,
		    MULTI_BOOT_ARCHIVE, root_opt, NULL);
		if (ent != NULL) {
			change_kernel = 1;
		}
	}
	if (ent == NULL)
		return (add_boot_entry(mp, title, root_opt ? NULL : root,
		    kernel, mod_kernel, module));

	/* replace title of exiting entry and delete root line */
	lp = ent->start;
	lp = lp->next;	/* title line */
	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[TITLE_CMD], menu_cmds[SEP_CMD], title);
	free(lp->arg);
	free(lp->line);
	lp->arg = s_strdup(title);
	lp->line = s_strdup(linebuf);

	lp = lp->next;	/* root line */
	if (strcmp(lp->cmd, menu_cmds[ROOT_CMD]) == 0) {
		if (root_opt) {		/* root line not needed */
			line_t *tmp = lp;
			lp = lp->next;
			unlink_line(mp, tmp);
			line_free(tmp);
		} else
			lp = lp->next;
	}

	if (change_kernel) {
		/*
		 * We're upgrading from multiboot to directboot.
		 */
		if (strcmp(lp->cmd, menu_cmds[KERNEL_CMD]) == 0) {
			(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
			    menu_cmds[KERNEL_DOLLAR_CMD], menu_cmds[SEP_CMD],
			    kernel);
			free(lp->arg);
			free(lp->line);
			lp->arg = s_strdup(kernel);
			lp->line = s_strdup(linebuf);
			lp = lp->next;
		}
		if (strcmp(lp->cmd, menu_cmds[MODULE_CMD]) == 0) {
			(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
			    menu_cmds[MODULE_DOLLAR_CMD], menu_cmds[SEP_CMD],
			    module);
			free(lp->arg);
			free(lp->line);
			lp->arg = s_strdup(module);
			lp->line = s_strdup(linebuf);
			lp = lp->next;
		}
	}
	return (i);
}

/*ARGSUSED*/
static error_t
update_entry(menu_t *mp, char *menu_root, char *opt)
{
	FILE *fp;
	int entry;
	char *grubdisk, *title, *osdev, *osroot, *failsafe_kernel = NULL;
	struct stat sbuf;
	char failsafe[256];

	assert(mp);
	assert(opt);

	osdev = strtok(opt, ",");
	osroot = strtok(NULL, ",");
	if (osroot == NULL)
		osroot = menu_root;
	title = get_title(osroot);

	/* translate /dev/dsk name to grub disk name */
	fp = open_diskmap(osroot);
	if (fp == NULL) {
		bam_error(DISKMAP_FAIL, osdev);
		return (BAM_ERROR);
	}
	grubdisk = get_grubdisk(osdev, fp, menu_on_bootdev(menu_root, fp));
	(void) fclose(fp);
	if (grubdisk == NULL) {
		bam_error(DISKMAP_FAIL, osdev);
		return (BAM_ERROR);
	}

	/* add the entry for normal Solaris */
	if (bam_direct == BAM_DIRECT_DBOOT) {
		entry = update_boot_entry(mp, title, grubdisk,
		    DIRECT_BOOT_KERNEL, NULL, DIRECT_BOOT_ARCHIVE,
		    osroot == menu_root);
		if ((entry != BAM_ERROR) && (bam_is_hv == BAM_HV_PRESENT)) {
			(void) update_boot_entry(mp, NEW_HV_ENTRY, grubdisk,
			    XEN_MENU, KERNEL_MODULE_LINE, DIRECT_BOOT_ARCHIVE,
			    osroot == menu_root);
		}
	} else {
		entry = update_boot_entry(mp, title, grubdisk, MULTI_BOOT,
		    NULL, MULTI_BOOT_ARCHIVE, osroot == menu_root);
	}

	/*
	 * Add the entry for failsafe archive.  On a bfu'd system, the
	 * failsafe may be different than the installed kernel.
	 */
	(void) snprintf(failsafe, sizeof (failsafe), "%s%s", osroot, MINIROOT);
	if (stat(failsafe, &sbuf) == 0) {

		/* Figure out where the kernel line should point */
		(void) snprintf(failsafe, sizeof (failsafe), "%s%s", osroot,
		    DIRECT_BOOT_FAILSAFE_KERNEL);
		if (stat(failsafe, &sbuf) == 0) {
			failsafe_kernel = DIRECT_BOOT_FAILSAFE_LINE;
		} else {
			(void) snprintf(failsafe, sizeof (failsafe), "%s%s",
			    osroot, MULTI_BOOT_FAILSAFE);
			if (stat(failsafe, &sbuf) == 0) {
				failsafe_kernel = MULTI_BOOT_FAILSAFE_LINE;
			}
		}
		if (failsafe_kernel != NULL) {
			(void) update_boot_entry(mp, FAILSAFE_TITLE, grubdisk,
			    failsafe_kernel, NULL, MINIROOT,
			    osroot == menu_root);
		}
	}
	free(grubdisk);

	if (entry == BAM_ERROR) {
		return (BAM_ERROR);
	}
	(void) set_global(mp, menu_cmds[DEFAULT_CMD], entry);
	return (BAM_WRITE);
}

static char *
read_grub_root(void)
{
	FILE *fp;
	struct stat sb;
	char buf[BAM_MAXLINE];
	char *rootstr;

	if (stat(GRUB_slice, &sb) != 0) {
		bam_error(MISSING_SLICE_FILE, GRUB_slice, strerror(errno));
		return (NULL);
	}

	if (stat(GRUB_root, &sb) != 0) {
		bam_error(MISSING_ROOT_FILE, GRUB_root, strerror(errno));
		return (NULL);
	}

	fp = fopen(GRUB_root, "r");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, GRUB_root, strerror(errno));
		return (NULL);
	}

	if (s_fgets(buf, sizeof (buf), fp) == NULL) {
		bam_error(EMPTY_FILE, GRUB_root, strerror(errno));
		(void) fclose(fp);
		return (NULL);
	}

	/*
	 * Copy buf here as check below may trash the buffer
	 */
	rootstr = s_strdup(buf);

	if (s_fgets(buf, sizeof (buf), fp) != NULL) {
		bam_error(BAD_ROOT_FILE, GRUB_root);
		free(rootstr);
		rootstr = NULL;
	}

	(void) fclose(fp);

	return (rootstr);
}

static void
save_default_entry(menu_t *mp, const char *which)
{
	int lineNum, entryNum;
	int entry = 0;	/* default is 0 */
	char linebuf[BAM_MAXLINE];
	line_t *lp = mp->curdefault;

	if (mp->start) {
		lineNum = mp->end->lineNum;
		entryNum = mp->end->entryNum;
	} else {
		lineNum = LINE_INIT;
		entryNum = ENTRY_INIT;
	}

	if (lp)
		entry = s_strtol(lp->arg);

	(void) snprintf(linebuf, sizeof (linebuf), "#%s%d", which, entry);
	line_parser(mp, linebuf, &lineNum, &entryNum);
}

static void
restore_default_entry(menu_t *mp, const char *which, line_t *lp)
{
	int entry;
	char *str;

	if (lp == NULL)
		return;		/* nothing to restore */

	str = lp->arg + strlen(which);
	entry = s_strtol(str);
	(void) set_global(mp, menu_cmds[DEFAULT_CMD], entry);

	/* delete saved old default line */
	unlink_line(mp, lp);
	line_free(lp);
}

/*
 * This function is for supporting reboot with args.
 * The opt value can be:
 * NULL		delete temp entry, if present
 * entry=#	switches default entry to 1
 * else		treated as boot-args and setup a temperary menu entry
 *		and make it the default
 */
#define	REBOOT_TITLE	"Solaris_reboot_transient"

/*ARGSUSED*/
static error_t
update_temp(menu_t *mp, char *menupath, char *opt)
{
	int entry;
	char *grubdisk, *rootdev, *path, *opt_ptr;
	char kernbuf[BUFSIZ];
	char args_buf[BUFSIZ];
	struct stat sb;

	assert(mp);

	/* If no option, delete exiting reboot menu entry */
	if (opt == NULL) {
		entry_t *ent = find_boot_entry(mp, REBOOT_TITLE, NULL, NULL,
		    NULL, 0, &entry);
		if (ent == NULL)	/* not found is ok */
			return (BAM_SUCCESS);
		(void) do_delete(mp, entry);
		restore_default_entry(mp, BAM_OLDDEF, mp->olddefault);
		mp->olddefault = NULL;
		return (BAM_WRITE);
	}

	/* if entry= is specified, set the default entry */
	if (strncmp(opt, "entry=", strlen("entry=")) == 0 &&
	    selector(mp, opt, &entry, NULL) == BAM_SUCCESS) {
		/* this is entry=# option */
		return (set_global(mp, menu_cmds[DEFAULT_CMD], entry));
	}

	/*
	 * add a new menu entry base on opt and make it the default
	 */
	grubdisk = NULL;
	if (stat(GRUB_slice, &sb) != 0) {
		/*
		 * 1. First get root disk name from mnttab
		 * 2. Translate disk name to grub name
		 * 3. Add the new menu entry
		 */
		rootdev = get_special("/");
		if (rootdev) {
			grubdisk = os_to_grubdisk(rootdev, 1);
			free(rootdev);
		}
	} else {
		/*
		 * This is an LU BE. The GRUB_root file
		 * contains entry for GRUB's "root" cmd.
		 */
		grubdisk = read_grub_root();
	}
	if (grubdisk == NULL) {
		bam_error(REBOOT_WITH_ARGS_FAILED);
		return (BAM_ERROR);
	}

	/* add an entry for Solaris reboot */
	if (bam_direct == BAM_DIRECT_DBOOT) {
		if (opt[0] == '-') {
			/* It's an option - first see if boot-file is set */
			if (set_kernel(mp, KERNEL_CMD, NULL, kernbuf, BUFSIZ)
			    != BAM_SUCCESS)
				return (BAM_ERROR);
			if (kernbuf[0] == '\0')
				(void) strncpy(kernbuf, DIRECT_BOOT_KERNEL,
				    BUFSIZ);
			(void) strlcat(kernbuf, " ", BUFSIZ);
			(void) strlcat(kernbuf, opt, BUFSIZ);
		} else if (opt[0] == '/') {
			/* It's a full path, so write it out. */
			(void) strlcpy(kernbuf, opt, BUFSIZ);

			/*
			 * If someone runs:
			 *
			 *	# eeprom boot-args='-kd'
			 *	# reboot /platform/i86pc/kernel/unix
			 *
			 * we want to use the boot-args as part of the boot
			 * line.  On the other hand, if someone runs:
			 *
			 *	# reboot "/platform/i86pc/kernel/unix -kd"
			 *
			 * we don't need to mess with boot-args.  If there's
			 * no space in the options string, assume we're in the
			 * first case.
			 */
			if (strchr(opt, ' ') == NULL) {
				if (set_kernel(mp, ARGS_CMD, NULL, args_buf,
				    BUFSIZ) != BAM_SUCCESS)
					return (BAM_ERROR);

				if (args_buf[0] != '\0') {
					(void) strlcat(kernbuf, " ", BUFSIZ);
					(void) strlcat(kernbuf, args_buf,
					    BUFSIZ);
				}
			}
		} else {
			/*
			 * It may be a partial path, or it may be a partial
			 * path followed by options.  Assume that only options
			 * follow a space.  If someone sends us a kernel path
			 * that includes a space, they deserve to be broken.
			 */
			opt_ptr = strchr(opt, ' ');
			if (opt_ptr != NULL) {
				*opt_ptr = '\0';
			}

			path = expand_path(opt);
			if (path != NULL) {
				(void) strlcpy(kernbuf, path, BUFSIZ);
				free(path);

				/*
				 * If there were options given, use those.
				 * Otherwise, copy over the default options.
				 */
				if (opt_ptr != NULL) {
					/* Restore the space in opt string */
					*opt_ptr = ' ';
					(void) strlcat(kernbuf, opt_ptr,
					    BUFSIZ);
				} else {
					if (set_kernel(mp, ARGS_CMD, NULL,
					    args_buf, BUFSIZ) != BAM_SUCCESS)
						return (BAM_ERROR);

					if (args_buf[0] != '\0') {
						(void) strlcat(kernbuf, " ",
						    BUFSIZ);
						(void) strlcat(kernbuf,
						    args_buf, BUFSIZ);
					}
				}
			} else {
				bam_error(UNKNOWN_KERNEL, opt);
				bam_print_stderr(UNKNOWN_KERNEL_REBOOT);
				return (BAM_ERROR);
			}
		}
		entry = add_boot_entry(mp, REBOOT_TITLE, grubdisk, kernbuf,
		    NULL, NULL);
	} else {
		(void) snprintf(kernbuf, sizeof (kernbuf), "%s %s",
		    MULTI_BOOT, opt);
		entry = add_boot_entry(mp, REBOOT_TITLE, grubdisk, kernbuf,
		    NULL, MULTI_BOOT_ARCHIVE);
	}
	free(grubdisk);

	if (entry == BAM_ERROR) {
		bam_error(REBOOT_WITH_ARGS_FAILED);
		return (BAM_ERROR);
	}

	save_default_entry(mp, BAM_OLDDEF);
	(void) set_global(mp, menu_cmds[DEFAULT_CMD], entry);
	return (BAM_WRITE);
}

static error_t
set_global(menu_t *mp, char *globalcmd, int val)
{
	line_t *lp, *found, *last;
	char *cp, *str;
	char prefix[BAM_MAXLINE];
	size_t len;

	assert(mp);
	assert(globalcmd);

	if (strcmp(globalcmd, menu_cmds[DEFAULT_CMD]) == 0) {
		if (val < 0 || mp->end == NULL || val > mp->end->entryNum) {
			(void) snprintf(prefix, sizeof (prefix), "%d", val);
			bam_error(INVALID_ENTRY, prefix);
			return (BAM_ERROR);
		}
	}

	found = last = NULL;
	for (lp = mp->start; lp; lp = lp->next) {
		if (lp->flags != BAM_GLOBAL)
			continue;

		last = lp; /* track the last global found */

		if (lp->cmd == NULL) {
			bam_error(NO_CMD, lp->lineNum);
			continue;
		}
		if (strcmp(globalcmd, lp->cmd) != 0)
			continue;

		if (found) {
			bam_error(DUP_CMD, globalcmd, lp->lineNum, bam_root);
		}
		found = lp;
	}

	if (found == NULL) {
		lp = s_calloc(1, sizeof (line_t));
		if (last == NULL) {
			lp->next = mp->start;
			mp->start = lp;
			mp->end = (mp->end) ? mp->end : lp;
		} else {
			lp->next = last->next;
			last->next = lp;
			if (lp->next == NULL)
				mp->end = lp;
		}
		lp->flags = BAM_GLOBAL; /* other fields not needed for writes */
		len = strlen(globalcmd) + strlen(menu_cmds[SEP_CMD]);
		len += 10;	/* val < 10 digits */
		lp->line = s_calloc(1, len);
		(void) snprintf(lp->line, len, "%s%s%d",
		    globalcmd, menu_cmds[SEP_CMD], val);
		return (BAM_WRITE);
	}

	/*
	 * We are changing an existing entry. Retain any prefix whitespace,
	 * but overwrite everything else. This preserves tabs added for
	 * readability.
	 */
	str = found->line;
	cp = prefix;
	while (*str == ' ' || *str == '\t')
		*(cp++) = *(str++);
	*cp = '\0'; /* Terminate prefix */
	len = strlen(prefix) + strlen(globalcmd);
	len += strlen(menu_cmds[SEP_CMD]) + 10;

	free(found->line);
	found->line = s_calloc(1, len);
	(void) snprintf(found->line, len,
	    "%s%s%s%d", prefix, globalcmd, menu_cmds[SEP_CMD], val);

	return (BAM_WRITE); /* need a write to menu */
}

/*
 * partial_path may be anything like "kernel/unix" or "kmdb".  Try to
 * expand it to a full unix path.  The calling function is expected to
 * output a message if an error occurs and NULL is returned.
 */
static char *
expand_path(const char *partial_path)
{
	int new_path_len;
	char *new_path, new_path2[PATH_MAX];
	struct stat sb;

	new_path_len = strlen(partial_path) + 64;
	new_path = s_calloc(1, new_path_len);

	/* First, try the simplest case - something like "kernel/unix" */
	(void) snprintf(new_path, new_path_len, "/platform/i86pc/%s",
	    partial_path);
	if (stat(new_path, &sb) == 0) {
		return (new_path);
	}

	if (strcmp(partial_path, "kmdb") == 0) {
		(void) snprintf(new_path, new_path_len, "%s -k",
		    DIRECT_BOOT_KERNEL);
		return (new_path);
	}

	/*
	 * We've quickly reached unsupported usage.  Try once more to
	 * see if we were just given a glom name.
	 */
	(void) snprintf(new_path, new_path_len, "/platform/i86pc/%s/unix",
	    partial_path);
	(void) snprintf(new_path2, PATH_MAX, "/platform/i86pc/%s/amd64/unix",
	    partial_path);
	if (stat(new_path, &sb) == 0) {
		if (stat(new_path2, &sb) == 0) {
			/*
			 * We matched both, so we actually
			 * want to write the $ISADIR version.
			 */
			(void) snprintf(new_path, new_path_len,
			    "/platform/i86pc/kernel/%s/$ISADIR/unix",
			    partial_path);
		}
		return (new_path);
	}

	free(new_path);
	return (NULL);
}

/*
 * The kernel cmd and arg have been changed, so
 * check whether the archive line needs to change.
 */
static void
set_archive_line(entry_t *entryp, line_t *kernelp)
{
	line_t *lp = entryp->start;
	char *new_archive;
	menu_cmd_t m_cmd;

	for (; lp != NULL; lp = lp->next) {
		if (strncmp(lp->cmd, menu_cmds[MODULE_CMD],
		    sizeof (menu_cmds[MODULE_CMD]) - 1) == 0) {
			break;
		}
		if (lp == entryp->end)
			return;
	}
	if (lp == NULL)
		return;

	if (strstr(kernelp->arg, "$ISADIR") != NULL) {
		new_archive = DIRECT_BOOT_ARCHIVE;
		m_cmd = MODULE_DOLLAR_CMD;
	} else if (strstr(kernelp->arg, "amd64") != NULL) {
		new_archive = DIRECT_BOOT_ARCHIVE_64;
		m_cmd = MODULE_CMD;
	} else {
		new_archive = DIRECT_BOOT_ARCHIVE_32;
		m_cmd = MODULE_CMD;
	}

	if (strcmp(lp->arg, new_archive) == 0)
		return;

	if (strcmp(lp->cmd, menu_cmds[m_cmd]) != 0) {
		free(lp->cmd);
		lp->cmd = s_strdup(menu_cmds[m_cmd]);
	}

	free(lp->arg);
	lp->arg = s_strdup(new_archive);
	update_line(lp);
}

/*
 * Title for an entry to set properties that once went in bootenv.rc.
 */
#define	BOOTENV_RC_TITLE	"Solaris bootenv rc"

/*
 * If path is NULL, return the kernel (optnum == KERNEL_CMD) or arguments
 * (optnum == ARGS_CMD) in the argument buf.  If path is a zero-length
 * string, reset the value to the default.  If path is a non-zero-length
 * string, set the kernel or arguments.
 */
static error_t
set_kernel(menu_t *mp, menu_cmd_t optnum, char *path, char *buf, size_t bufsize)
{
	int entryNum, rv = BAM_SUCCESS, free_new_path = 0;
	entry_t *entryp;
	line_t *ptr, *kernelp;
	char *new_arg, *old_args, *space;
	char *grubdisk, *rootdev, *new_path;
	char old_space;
	size_t old_kernel_len, new_str_len;
	struct stat sb;

	assert(bufsize > 0);

	ptr = kernelp = NULL;
	new_arg = old_args = space = NULL;
	grubdisk = rootdev = new_path = NULL;
	buf[0] = '\0';

	if (bam_direct != BAM_DIRECT_DBOOT) {
		bam_error(NOT_DBOOT, optnum == KERNEL_CMD ? "kernel" : "args");
		return (BAM_ERROR);
	}

	/*
	 * If a user changed the default entry to a non-bootadm controlled
	 * one, we don't want to mess with it.  Just print an error and
	 * return.
	 */
	if (mp->curdefault) {
		entryNum = s_strtol(mp->curdefault->arg);
		for (entryp = mp->entries; entryp; entryp = entryp->next) {
			if (entryp->entryNum == entryNum)
				break;
		}
		if ((entryp != NULL) &&
		    ((entryp->flags & (BAM_ENTRY_BOOTADM|BAM_ENTRY_LU)) == 0)) {
			bam_error(DEFAULT_NOT_BAM);
			return (BAM_ERROR);
		}
	}

	entryNum = -1;
	entryp = find_boot_entry(mp, BOOTENV_RC_TITLE, NULL, NULL, NULL, 0,
	    &entryNum);

	if (entryp != NULL) {
		for (ptr = entryp->start; ptr && ptr != entryp->end;
		    ptr = ptr->next) {
			if (strncmp(ptr->cmd, menu_cmds[KERNEL_CMD],
			    sizeof (menu_cmds[KERNEL_CMD]) - 1) == 0) {
				kernelp = ptr;
				break;
			}
		}
		if (kernelp == NULL) {
			bam_error(NO_KERNEL, entryNum);
			return (BAM_ERROR);
		}

		old_kernel_len = strcspn(kernelp->arg, " \t");
		space = old_args = kernelp->arg + old_kernel_len;
		while ((*old_args == ' ') || (*old_args == '\t'))
			old_args++;
	}

	if (path == NULL) {
		/* Simply report what was found */
		if (kernelp == NULL)
			return (BAM_SUCCESS);

		if (optnum == ARGS_CMD) {
			if (old_args[0] != '\0')
				(void) strlcpy(buf, old_args, bufsize);
		} else {
			/*
			 * We need to print the kernel, so we just turn the
			 * first space into a '\0' and print the beginning.
			 * We don't print anything if it's the default kernel.
			 */
			old_space = *space;
			*space = '\0';
			if (strcmp(kernelp->arg, DIRECT_BOOT_KERNEL) != 0)
				(void) strlcpy(buf, kernelp->arg, bufsize);
			*space = old_space;
		}
		return (BAM_SUCCESS);
	}

	/*
	 * First, check if we're resetting an entry to the default.
	 */
	if ((path[0] == '\0') ||
	    ((optnum == KERNEL_CMD) &&
	    (strcmp(path, DIRECT_BOOT_KERNEL) == 0))) {
		if ((entryp == NULL) || (kernelp == NULL)) {
			/* No previous entry, it's already the default */
			return (BAM_SUCCESS);
		}

		/*
		 * Check if we can delete the entry.  If we're resetting the
		 * kernel command, and the args is already empty, or if we're
		 * resetting the args command, and the kernel is already the
		 * default, we can restore the old default and delete the entry.
		 */
		if (((optnum == KERNEL_CMD) &&
		    ((old_args == NULL) || (old_args[0] == '\0'))) ||
		    ((optnum == ARGS_CMD) &&
		    (strncmp(kernelp->arg, DIRECT_BOOT_KERNEL,
		    sizeof (DIRECT_BOOT_KERNEL) - 1) == 0))) {
			kernelp = NULL;
			(void) do_delete(mp, entryNum);
			restore_default_entry(mp, BAM_OLD_RC_DEF,
			    mp->old_rc_default);
			mp->old_rc_default = NULL;
			rv = BAM_WRITE;
			goto done;
		}

		if (optnum == KERNEL_CMD) {
			/*
			 * At this point, we've already checked that old_args
			 * and entryp are valid pointers.  The "+ 2" is for
			 * a space a the string termination character.
			 */
			new_str_len = (sizeof (DIRECT_BOOT_KERNEL) - 1) +
			    strlen(old_args) + 2;
			new_arg = s_calloc(1, new_str_len);
			(void) snprintf(new_arg, new_str_len, "%s %s",
			    DIRECT_BOOT_KERNEL, old_args);
			free(kernelp->arg);
			kernelp->arg = new_arg;

			/*
			 * We have changed the kernel line, so we may need
			 * to update the archive line as well.
			 */
			set_archive_line(entryp, kernelp);
		} else {
			/*
			 * We're resetting the boot args to nothing, so
			 * we only need to copy the kernel.  We've already
			 * checked that the kernel is not the default.
			 */
			new_arg = s_calloc(1, old_kernel_len + 1);
			(void) snprintf(new_arg, old_kernel_len + 1, "%s",
			    kernelp->arg);
			free(kernelp->arg);
			kernelp->arg = new_arg;
		}
		rv = BAM_WRITE;
		goto done;
	}

	/*
	 * Expand the kernel file to a full path, if necessary
	 */
	if ((optnum == KERNEL_CMD) && (path[0] != '/')) {
		new_path = expand_path(path);
		if (new_path == NULL) {
			bam_error(UNKNOWN_KERNEL, path);
			return (BAM_ERROR);
		}
		free_new_path = 1;
	} else {
		new_path = path;
		free_new_path = 0;
	}

	/*
	 * At this point, we know we're setting a new value.  First, take care
	 * of the case where there was no previous entry.
	 */
	if (entryp == NULL) {
		/* Similar to code in update_temp */
		if (stat(GRUB_slice, &sb) != 0) {
			/*
			 * 1. First get root disk name from mnttab
			 * 2. Translate disk name to grub name
			 * 3. Add the new menu entry
			 */
			rootdev = get_special("/");
			if (rootdev) {
				grubdisk = os_to_grubdisk(rootdev, 1);
				free(rootdev);
			}
		} else {
			/*
			 * This is an LU BE. The GRUB_root file
			 * contains entry for GRUB's "root" cmd.
			 */
			grubdisk = read_grub_root();
		}
		if (grubdisk == NULL) {
			bam_error(REBOOT_WITH_ARGS_FAILED);
			rv = BAM_ERROR;
			goto done;
		}
		if (optnum == KERNEL_CMD) {
			entryNum = add_boot_entry(mp, BOOTENV_RC_TITLE,
			    grubdisk, new_path, NULL, NULL);
		} else {
			new_str_len = strlen(DIRECT_BOOT_KERNEL) +
			    strlen(path) + 8;
			new_arg = s_calloc(1, new_str_len);

			(void) snprintf(new_arg, new_str_len, "%s %s",
			    DIRECT_BOOT_KERNEL, path);
			entryNum = add_boot_entry(mp, BOOTENV_RC_TITLE,
			    grubdisk, new_arg, NULL, DIRECT_BOOT_ARCHIVE);
		}
		save_default_entry(mp, BAM_OLD_RC_DEF);
		(void) set_global(mp, menu_cmds[DEFAULT_CMD], entryNum);
		rv = BAM_WRITE;
		goto done;
	}

	/*
	 * There was already an bootenv entry which we need to edit.
	 */
	if (optnum == KERNEL_CMD) {
		new_str_len = strlen(new_path) + strlen(old_args) + 2;
		new_arg = s_calloc(1, new_str_len);
		(void) snprintf(new_arg, new_str_len, "%s %s", new_path,
		    old_args);
		free(kernelp->arg);
		kernelp->arg = new_arg;

		/*
		 * If we have changed the kernel line, we may need to update
		 * the archive line as well.
		 */
		set_archive_line(entryp, kernelp);
	} else {
		new_str_len = old_kernel_len + strlen(path) + 8;
		new_arg = s_calloc(1, new_str_len);
		(void) strncpy(new_arg, kernelp->arg, old_kernel_len);
		(void) strlcat(new_arg, " ", new_str_len);
		(void) strlcat(new_arg, path, new_str_len);
		free(kernelp->arg);
		kernelp->arg = new_arg;
	}
	rv = BAM_WRITE;

done:
	if ((rv == BAM_WRITE) && kernelp)
		update_line(kernelp);
	if (free_new_path)
		free(new_path);
	return (rv);
}

/*ARGSUSED*/
static error_t
set_option(menu_t *mp, char *menu_path, char *opt)
{
	int optnum, optval;
	char *val;
	char buf[BUFSIZ] = "";
	error_t rv;

	assert(mp);
	assert(opt);

	val = strchr(opt, '=');
	if (val != NULL) {
		*val = '\0';
	}

	if (strcmp(opt, "default") == 0) {
		optnum = DEFAULT_CMD;
	} else if (strcmp(opt, "timeout") == 0) {
		optnum = TIMEOUT_CMD;
	} else if (strcmp(opt, menu_cmds[KERNEL_CMD]) == 0) {
		optnum = KERNEL_CMD;
	} else if (strcmp(opt, menu_cmds[ARGS_CMD]) == 0) {
		optnum = ARGS_CMD;
	} else {
		bam_error(INVALID_ENTRY, opt);
		return (BAM_ERROR);
	}

	/*
	 * kernel and args are allowed without "=new_value" strings.  All
	 * others cause errors
	 */
	if ((val == NULL) && (optnum != KERNEL_CMD) && (optnum != ARGS_CMD)) {
		bam_error(INVALID_ENTRY, opt);
		return (BAM_ERROR);
	} else if (val != NULL) {
		*val = '=';
	}

	if ((optnum == KERNEL_CMD) || (optnum == ARGS_CMD)) {
		rv = set_kernel(mp, optnum, val ? val + 1 : NULL, buf, BUFSIZ);
		if ((rv == BAM_SUCCESS) && (buf[0] != '\0'))
			(void) printf("%s\n", buf);
		return (rv);
	} else {
		optval = s_strtol(val + 1);
		return (set_global(mp, menu_cmds[optnum], optval));
	}
}

/*
 * The quiet argument suppresses messages. This is used
 * when invoked in the context of other commands (e.g. list_entry)
 */
static error_t
read_globals(menu_t *mp, char *menu_path, char *globalcmd, int quiet)
{
	line_t *lp;
	char *arg;
	int done, ret = BAM_SUCCESS;

	assert(mp);
	assert(menu_path);
	assert(globalcmd);

	if (mp->start == NULL) {
		if (!quiet)
			bam_error(NO_MENU, menu_path);
		return (BAM_ERROR);
	}

	done = 0;
	for (lp = mp->start; lp; lp = lp->next) {
		if (lp->flags != BAM_GLOBAL)
			continue;

		if (lp->cmd == NULL) {
			if (!quiet)
				bam_error(NO_CMD, lp->lineNum);
			continue;
		}

		if (strcmp(globalcmd, lp->cmd) != 0)
			continue;

		/* Found global. Check for duplicates */
		if (done && !quiet) {
			bam_error(DUP_CMD, globalcmd, lp->lineNum, bam_root);
			ret = BAM_ERROR;
		}

		arg = lp->arg ? lp->arg : "";
		bam_print(GLOBAL_CMD, globalcmd, arg);
		done = 1;
	}

	if (!done && bam_verbose)
		bam_print(NO_ENTRY, globalcmd);

	return (ret);
}

static error_t
menu_write(char *root, menu_t *mp)
{
	return (list2file(root, MENU_TMP, GRUB_MENU, mp->start));
}

static void
line_free(line_t *lp)
{
	if (lp == NULL)
		return;

	if (lp->cmd)
		free(lp->cmd);
	if (lp->sep)
		free(lp->sep);
	if (lp->arg)
		free(lp->arg);
	if (lp->line)
		free(lp->line);
	free(lp);
}

static void
linelist_free(line_t *start)
{
	line_t *lp;

	while (start) {
		lp = start;
		start = start->next;
		line_free(lp);
	}
}

static void
filelist_free(filelist_t *flistp)
{
	linelist_free(flistp->head);
	flistp->head = NULL;
	flistp->tail = NULL;
}

static void
menu_free(menu_t *mp)
{
	entry_t *ent, *tmp;
	assert(mp);

	if (mp->start)
		linelist_free(mp->start);
	ent = mp->entries;
	while (ent) {
		tmp = ent;
		ent = tmp->next;
		free(tmp);
	}

	free(mp);
}

/*
 * Utility routines
 */


/*
 * Returns 0 on success
 * Any other value indicates an error
 */
static int
exec_cmd(char *cmdline, char *output, int64_t osize)
{
	char buf[BUFSIZ];
	int ret;
	FILE *ptr;
	size_t len;
	sigset_t set;
	void (*disp)(int);

	/*
	 * For security
	 * - only absolute paths are allowed
	 * - set IFS to space and tab
	 */
	if (*cmdline != '/') {
		bam_error(ABS_PATH_REQ, cmdline);
		return (-1);
	}
	(void) putenv("IFS= \t");

	/*
	 * We may have been exec'ed with SIGCHLD blocked
	 * unblock it here
	 */
	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGCHLD);
	if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0) {
		bam_error(CANT_UNBLOCK_SIGCHLD, strerror(errno));
		return (-1);
	}

	/*
	 * Set SIGCHLD disposition to SIG_DFL for popen/pclose
	 */
	disp = sigset(SIGCHLD, SIG_DFL);
	if (disp == SIG_ERR) {
		bam_error(FAILED_SIG, strerror(errno));
		return (-1);
	}
	if (disp == SIG_HOLD) {
		bam_error(BLOCKED_SIG, cmdline);
		return (-1);
	}

	ptr = popen(cmdline, "r");
	if (ptr == NULL) {
		bam_error(POPEN_FAIL, cmdline, strerror(errno));
		return (-1);
	}

	/*
	 * If we simply do a pclose() following a popen(), pclose()
	 * will close the reader end of the pipe immediately even
	 * if the child process has not started/exited. pclose()
	 * does wait for cmd to terminate before returning though.
	 * When the executed command writes its output to the pipe
	 * there is no reader process and the command dies with
	 * SIGPIPE. To avoid this we read repeatedly until read
	 * terminates with EOF. This indicates that the command
	 * (writer) has closed the pipe and we can safely do a
	 * pclose().
	 *
	 * Since pclose() does wait for the command to exit,
	 * we can safely reap the exit status of the command
	 * from the value returned by pclose()
	 */
	while (fgets(buf, sizeof (buf), ptr) != NULL) {
		/* if (bam_verbose)  XXX */
			bam_print(PRINT_NO_NEWLINE, buf);
		if (output && osize > 0) {
			(void) snprintf(output, osize, "%s", buf);
			len = strlen(buf);
			output += len;
			osize -= len;
		}
	}

	ret = pclose(ptr);
	if (ret == -1) {
		bam_error(PCLOSE_FAIL, cmdline, strerror(errno));
		return (-1);
	}

	if (WIFEXITED(ret)) {
		return (WEXITSTATUS(ret));
	} else {
		bam_error(EXEC_FAIL, cmdline, ret);
		return (-1);
	}
}

/*
 * Since this function returns -1 on error
 * it cannot be used to convert -1. However,
 * that is sufficient for what we need.
 */
static long
s_strtol(char *str)
{
	long l;
	char *res = NULL;

	if (str == NULL) {
		return (-1);
	}

	errno = 0;
	l = strtol(str, &res, 10);
	if (errno || *res != '\0') {
		return (-1);
	}

	return (l);
}

/*
 * Wrapper around fputs, that adds a newline (since fputs doesn't)
 */
static int
s_fputs(char *str, FILE *fp)
{
	char linebuf[BAM_MAXLINE];

	(void) snprintf(linebuf, sizeof (linebuf), "%s\n", str);
	return (fputs(linebuf, fp));
}

/*
 * Wrapper around fgets, that strips newlines returned by fgets
 */
char *
s_fgets(char *buf, int buflen, FILE *fp)
{
	int n;

	buf = fgets(buf, buflen, fp);
	if (buf) {
		n = strlen(buf);
		if (n == buflen - 1 && buf[n-1] != '\n')
			bam_error(TOO_LONG, buflen - 1, buf);
		buf[n-1] = (buf[n-1] == '\n') ? '\0' : buf[n-1];
	}

	return (buf);
}

void *
s_calloc(size_t nelem, size_t sz)
{
	void *ptr;

	ptr = calloc(nelem, sz);
	if (ptr == NULL) {
		bam_error(NO_MEM, nelem*sz);
		bam_exit(1);
	}
	return (ptr);
}

void *
s_realloc(void *ptr, size_t sz)
{
	ptr = realloc(ptr, sz);
	if (ptr == NULL) {
		bam_error(NO_MEM, sz);
		bam_exit(1);
	}
	return (ptr);
}

static char *
s_strdup(char *str)
{
	char *ptr;

	if (str == NULL)
		return (NULL);

	ptr = strdup(str);
	if (ptr == NULL) {
		bam_error(NO_MEM, strlen(str) + 1);
		bam_exit(1);
	}
	return (ptr);
}

/*
 * Returns 1 if amd64 (or sparc, for syncing x86 diskless clients)
 * Returns 0 otherwise
 */
static int
is_amd64(void)
{
	static int amd64 = -1;
	char isabuf[257];	/* from sysinfo(2) manpage */

	if (amd64 != -1)
		return (amd64);

	if (sysinfo(SI_ISALIST, isabuf, sizeof (isabuf)) > 0 &&
	    strncmp(isabuf, "amd64 ", strlen("amd64 ")) == 0)
		amd64 = 1;
	else if (strstr(isabuf, "i386") == NULL)
		amd64 = 1;		/* diskless server */
	else
		amd64 = 0;

	return (amd64);
}

static void
append_to_flist(filelist_t *flistp, char *s)
{
	line_t *lp;

	lp = s_calloc(1, sizeof (line_t));
	lp->line = s_strdup(s);
	if (flistp->head == NULL)
		flistp->head = lp;
	else
		flistp->tail->next = lp;
	flistp->tail = lp;
}

#if defined(__i386)

UCODE_VENDORS;

/*ARGSUSED*/
static void
ucode_install(char *root)
{
	int i;

	for (i = 0; ucode_vendors[i].filestr != NULL; i++) {
		int cmd_len = PATH_MAX + 256;
		char cmd[PATH_MAX + 256];
		char file[PATH_MAX];
		char timestamp[PATH_MAX];
		struct stat fstatus, tstatus;
		struct utimbuf u_times;

		(void) snprintf(file, PATH_MAX, "%s/%s/%s-ucode.txt",
		    bam_root, UCODE_INSTALL_PATH, ucode_vendors[i].filestr);

		if (stat(file, &fstatus) != 0 || !(S_ISREG(fstatus.st_mode)))
			continue;

		(void) snprintf(timestamp, PATH_MAX, "%s.ts", file);

		if (stat(timestamp, &tstatus) == 0 &&
		    fstatus.st_mtime <= tstatus.st_mtime)
			continue;

		(void) snprintf(cmd, cmd_len, "/usr/sbin/ucodeadm -i -R "
		    "%s/%s/%s %s > /dev/null 2>&1", bam_root,
		    UCODE_INSTALL_PATH, ucode_vendors[i].vendorstr, file);
		if (system(cmd) != 0)
			return;

		if (creat(timestamp, S_IRUSR | S_IWUSR) == -1)
			return;

		u_times.actime = fstatus.st_atime;
		u_times.modtime = fstatus.st_mtime;
		(void) utime(timestamp, &u_times);
	}
}
#endif
