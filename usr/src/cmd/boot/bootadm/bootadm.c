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
 * Copyright (c) 2015 by Delphix. All rights reserved.
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright 2016 Nexenta Systems, Inc.
 */

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
#include <alloca.h>
#include <stdarg.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/statvfs.h>
#include <libnvpair.h>
#include <ftw.h>
#include <fcntl.h>
#include <strings.h>
#include <utime.h>
#include <sys/systeminfo.h>
#include <sys/dktp/fdisk.h>
#include <sys/param.h>
#include <dirent.h>
#include <ctype.h>
#include <libgen.h>
#include <sys/sysmacros.h>
#include <sys/elf.h>
#include <libscf.h>
#include <zlib.h>
#include <sys/lockfs.h>
#include <sys/filio.h>
#include <libbe.h>
#include <deflt.h>
#ifdef i386
#include <libfdisk.h>
#endif

#if !defined(_OBP)
#include <sys/ucode.h>
#endif

#include <pwd.h>
#include <grp.h>
#include <device_info.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <regex.h>
#include <locale.h>
#include <sys/mkdev.h>

#include "bootadm.h"

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif	/* TEXT_DOMAIN */

/* Type definitions */

/* Primary subcmds */
typedef enum {
	BAM_MENU = 3,
	BAM_ARCHIVE,
	BAM_INSTALL
} subcmd_t;

#define	LINE_INIT	0	/* lineNum initial value */
#define	ENTRY_INIT	-1	/* entryNum initial value */
#define	ALL_ENTRIES	-2	/* selects all boot entries */

#define	PARTNO_NOTFOUND -1	/* Solaris partition not found */
#define	PARTNO_EFI	-2	/* EFI partition table found */

#define	GRUB_DIR		"/boot/grub"
#define	GRUB_STAGE2		GRUB_DIR "/stage2"
#define	GRUB_MENU		"/boot/grub/menu.lst"
#define	MENU_TMP		"/boot/grub/menu.lst.tmp"
#define	GRUB_BACKUP_MENU	"/etc/lu/GRUB_backup_menu"
#define	RAMDISK_SPECIAL		"/dev/ramdisk/"
#define	STUBBOOT		"/stubboot"
#define	MULTIBOOT		"/platform/i86pc/multiboot"
#define	GRUBSIGN_DIR		"/boot/grub/bootsign"
#define	GRUBSIGN_BACKUP		"/etc/bootsign"
#define	GRUBSIGN_UFS_PREFIX	"rootfs"
#define	GRUBSIGN_ZFS_PREFIX	"pool_"
#define	GRUBSIGN_LU_PREFIX	"BE_"
#define	UFS_SIGNATURE_LIST	"/var/run/grub_ufs_signatures"
#define	ZFS_LEGACY_MNTPT	"/tmp/bootadm_mnt_zfs_legacy"

/* BE defaults */
#define	BE_DEFAULTS		"/etc/default/be"
#define	BE_DFLT_BE_HAS_GRUB	"BE_HAS_GRUB="

#define	BOOTADM_RDONLY_TEST	"BOOTADM_RDONLY_TEST"

/* lock related */
#define	BAM_LOCK_FILE		"/var/run/bootadm.lock"
#define	LOCK_FILE_PERMS		(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#define	CREATE_RAMDISK		"boot/solaris/bin/create_ramdisk"
#define	CREATE_DISKMAP		"boot/solaris/bin/create_diskmap"
#define	EXTRACT_BOOT_FILELIST	"boot/solaris/bin/extract_boot_filelist"
#define	GRUBDISK_MAP		"/var/run/solaris_grubdisk.map"

#define	GRUB_slice		"/etc/lu/GRUB_slice"
#define	GRUB_root		"/etc/lu/GRUB_root"
#define	GRUB_fdisk		"/etc/lu/GRUB_fdisk"
#define	GRUB_fdisk_target	"/etc/lu/GRUB_fdisk_target"
#define	FINDROOT_INSTALLGRUB	"/etc/lu/installgrub.findroot"
#define	LULIB			"/usr/lib/lu/lulib"
#define	LULIB_PROPAGATE_FILE	"lulib_propagate_file"
#define	CKSUM			"/usr/bin/cksum"
#define	LU_MENU_CKSUM		"/etc/lu/menu.cksum"
#define	BOOTADM			"/sbin/bootadm"

#define	INSTALLGRUB		"/sbin/installgrub"
#define	STAGE1			"/boot/grub/stage1"
#define	STAGE2			"/boot/grub/stage2"

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
	"findroot",	/* FINDROOT_CMD */
	"bootfs",	/* BOOTFS_CMD */
	NULL
};

#define	OPT_ENTRY_NUM	"entry"

/*
 * exec_cmd related
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

#define	FILE_STAT_TIMESTAMP	"boot/solaris/timestamp.cache"

/* Globals */
int bam_verbose;
int bam_force;
int bam_debug;
static char *prog;
static subcmd_t bam_cmd;
char *bam_root;
int bam_rootlen;
static int bam_root_readonly;
int bam_alt_root;
static int bam_extend = 0;
static int bam_purge = 0;
static char *bam_subcmd;
static char *bam_opt;
static char **bam_argv;
static char *bam_pool;
static int bam_argc;
static int bam_check;
static int bam_saved_check;
static int bam_smf_check;
static int bam_lock_fd = -1;
static int bam_zfs;
static int bam_mbr;
char rootbuf[PATH_MAX] = "/";
static int bam_update_all;
static int bam_alt_platform;
static char *bam_platform;
static char *bam_home_env = NULL;

/* function prototypes */
static void parse_args_internal(int, char *[]);
static void parse_args(int, char *argv[]);
static error_t bam_menu(char *, char *, int, char *[]);
static error_t bam_install(char *, char *);
static error_t bam_archive(char *, char *);

static void bam_lock(void);
static void bam_unlock(void);

static int exec_cmd(char *, filelist_t *);
static error_t read_globals(menu_t *, char *, char *, int);
static int menu_on_bootdisk(char *os_root, char *menu_root);
static menu_t *menu_read(char *);
static error_t menu_write(char *, menu_t *);
static void linelist_free(line_t *);
static void menu_free(menu_t *);
static void filelist_free(filelist_t *);
static error_t list2file(char *, char *, char *, line_t *);
static error_t list_entry(menu_t *, char *, char *);
static error_t list_setting(menu_t *, char *, char *);
static error_t delete_all_entries(menu_t *, char *, char *);
static error_t update_entry(menu_t *mp, char *menu_root, char *opt);
static error_t update_temp(menu_t *mp, char *dummy, char *opt);

static error_t install_bootloader(void);
static error_t update_archive(char *, char *);
static error_t list_archive(char *, char *);
static error_t update_all(char *, char *);
static error_t read_list(char *, filelist_t *);
static error_t set_option(menu_t *, char *, char *);
static error_t set_kernel(menu_t *, menu_cmd_t, char *, char *, size_t);
static error_t get_kernel(menu_t *, menu_cmd_t, char *, size_t);
static char *expand_path(const char *);

static long s_strtol(char *);
static int s_fputs(char *, FILE *);

static int is_amd64(void);
static char *get_machine(void);
static void append_to_flist(filelist_t *, char *);
static int ufs_add_to_sign_list(char *sign);
static error_t synchronize_BE_menu(void);

#if !defined(_OBP)
static void ucode_install();
#endif

/* Menu related sub commands */
static subcmd_defn_t menu_subcmds[] = {
	"set_option",		OPT_ABSENT,	set_option, 0,	/* PUB */
	"list_entry",		OPT_OPTIONAL,	list_entry, 1,	/* PUB */
	"delete_all_entries",	OPT_ABSENT,	delete_all_entries, 0, /* PVT */
	"update_entry",		OPT_REQ,	update_entry, 0, /* menu */
	"update_temp",		OPT_OPTIONAL,	update_temp, 0,	/* reboot */
	"upgrade",		OPT_ABSENT,	upgrade_menu, 0, /* menu */
	"list_setting",		OPT_OPTIONAL,	list_setting, 1, /* menu */
	"disable_hypervisor",	OPT_ABSENT,	cvt_to_metal, 0, /* menu */
	"enable_hypervisor",	OPT_ABSENT,	cvt_to_hyper, 0, /* menu */
	NULL,			0,		NULL, 0	/* must be last */
};

/* Archive related sub commands */
static subcmd_defn_t arch_subcmds[] = {
	"update",		OPT_ABSENT,	update_archive, 0, /* PUB */
	"update_all",		OPT_ABSENT,	update_all, 0,	/* PVT */
	"list",			OPT_OPTIONAL,	list_archive, 1, /* PUB */
	NULL,			0,		NULL, 0	/* must be last */
};

/* Install related sub commands */
static subcmd_defn_t inst_subcmds[] = {
	"install_bootloader",	OPT_ABSENT,	install_bootloader, 0, /* PUB */
	NULL,			0,		NULL, 0	/* must be last */
};

enum dircache_copy_opt {
	FILE32 = 0,
	FILE64,
	CACHEDIR_NUM
};

/*
 * Directory specific flags:
 * NEED_UPDATE : the specified archive needs to be updated
 * NO_MULTI : don't extend the specified archive, but recreate it
 */
#define	NEED_UPDATE		0x00000001
#define	NO_MULTI		0x00000002

#define	set_dir_flag(id, f)	(walk_arg.dirinfo[id].flags |= f)
#define	unset_dir_flag(id, f)	(walk_arg.dirinfo[id].flags &= ~f)
#define	is_dir_flag_on(id, f)	(walk_arg.dirinfo[id].flags & f ? 1 : 0)

#define	get_cachedir(id)	(walk_arg.dirinfo[id].cdir_path)
#define	get_updatedir(id)	(walk_arg.dirinfo[id].update_path)
#define	get_count(id)		(walk_arg.dirinfo[id].count)
#define	has_cachedir(id)	(walk_arg.dirinfo[id].has_dir)
#define	set_dir_present(id)	(walk_arg.dirinfo[id].has_dir = 1)

/*
 * dirinfo_t (specific cache directory information):
 * cdir_path:   path to the archive cache directory
 * update_path: path to the update directory (contains the files that will be
 *              used to extend the archive)
 * has_dir:	the specified cache directory is active
 * count:	the number of files to update
 * flags:	directory specific flags
 */
typedef struct _dirinfo {
	char	cdir_path[PATH_MAX];
	char	update_path[PATH_MAX];
	int	has_dir;
	int	count;
	int	flags;
} dirinfo_t;

/*
 * Update flags:
 * NEED_CACHE_DIR : cache directory is missing and needs to be created
 * IS_SPARC_TARGET : the target mountpoint is a SPARC environment
 * UPDATE_ERROR : an error occourred while traversing the list of files
 * RDONLY_FSCHK : the target filesystem is read-only
 * RAMDSK_FSCHK : the target filesystem is on a ramdisk
 */
#define	NEED_CACHE_DIR		0x00000001
#define	IS_SPARC_TARGET		0x00000002
#define	UPDATE_ERROR		0x00000004
#define	RDONLY_FSCHK		0x00000008
#define	INVALIDATE_CACHE	0x00000010

#define	is_flag_on(flag)	(walk_arg.update_flags & flag ? 1 : 0)
#define	set_flag(flag)		(walk_arg.update_flags |= flag)
#define	unset_flag(flag)	(walk_arg.update_flags &= ~flag)

/*
 * struct walk_arg :
 * update_flags: flags related to the current updating process
 * new_nvlp/old_nvlp: new and old list of archive-files / attributes pairs
 * sparcfile: list of file paths for mkisofs -path-list (SPARC only)
 */
static struct {
	int 		update_flags;
	nvlist_t 	*new_nvlp;
	nvlist_t 	*old_nvlp;
	FILE 		*sparcfile;
	dirinfo_t	dirinfo[CACHEDIR_NUM];
} walk_arg;

struct safefile {
	char *name;
	struct safefile *next;
};

static struct safefile *safefiles = NULL;

/*
 * svc:/system/filesystem/usr:default service checks for this file and
 * does a boot archive update and then reboot the system.
 */
#define	NEED_UPDATE_FILE "/etc/svc/volatile/boot_archive_needs_update"

/*
 * svc:/system/boot-archive-update:default checks for this file and
 * updates the boot archive.
 */
#define	NEED_UPDATE_SAFE_FILE "/etc/svc/volatile/boot_archive_safefile_update"

/* Thanks growisofs */
#define	CD_BLOCK	((off64_t)2048)
#define	VOLDESC_OFF	16
#define	DVD_BLOCK	(32*1024)
#define	MAX_IVDs	16

struct iso_pdesc {
    unsigned char type	[1];
    unsigned char id	[5];
    unsigned char void1	[80-5-1];
    unsigned char volume_space_size [8];
    unsigned char void2	[2048-80-8];
};

/*
 * COUNT_MAX:	maximum number of changed files to justify a multisession update
 * BA_SIZE_MAX:	maximum size of the boot_archive to justify a multisession
 * 		update
 */
#define	COUNT_MAX		50
#define	BA_SIZE_MAX		(50 * 1024 * 1024)

#define	bam_nowrite()		(bam_check || bam_smf_check)

static int sync_menu = 1;	/* whether we need to sync the BE menus */

static void
usage(void)
{
	(void) fprintf(stderr, "USAGE:\n");

	/* archive usage */
	(void) fprintf(stderr,
	    "\t%s update-archive [-vn] [-R altroot [-p platform]]\n", prog);
	(void) fprintf(stderr,
	    "\t%s list-archive [-R altroot [-p platform]]\n", prog);
#if defined(_OBP)
	(void) fprintf(stderr,
	    "\t%s install-bootloader [-fv] [-R altroot] [-P pool]\n", prog);
#else
	(void) fprintf(stderr,
	    "\t%s install-bootloader [-Mfv] [-R altroot] [-P pool]\n", prog);
#endif
#if !defined(_OBP)
	/* x86 only */
	(void) fprintf(stderr, "\t%s set-menu [-R altroot] key=value\n", prog);
	(void) fprintf(stderr, "\t%s list-menu [-R altroot]\n", prog);
#endif
}

/*
 * Best effort attempt to restore the $HOME value.
 */
static void
restore_env()
{
	char	home_env[PATH_MAX];

	if (bam_home_env) {
		(void) snprintf(home_env, sizeof (home_env), "HOME=%s",
		    bam_home_env);
		(void) putenv(home_env);
	}
}


#define		SLEEP_TIME	5
#define		MAX_TRIES	4

/*
 * Sanitize the environment in which bootadm will execute its sub-processes
 * (ex. mkisofs). This is done to prevent those processes from attempting
 * to access files (ex. .mkisofsrc) or stat paths that might be on NFS
 * or, potentially, insecure.
 */
static void
sanitize_env()
{
	int	stry = 0;

	/* don't depend on caller umask */
	(void) umask(0022);

	/* move away from a potential unsafe current working directory */
	while (chdir("/") == -1) {
		if (errno != EINTR) {
			bam_print("WARNING: unable to chdir to /");
			break;
		}
	}

	bam_home_env = getenv("HOME");
	while (bam_home_env != NULL && putenv("HOME=/") == -1) {
		if (errno == ENOMEM) {
			/* retry no more than MAX_TRIES times */
			if (++stry > MAX_TRIES) {
				bam_print("WARNING: unable to recover from "
				    "system memory pressure... aborting \n");
				bam_exit(EXIT_FAILURE);
			}
			/* memory is tight, try to sleep */
			bam_print("Attempting to recover from memory pressure: "
			    "sleeping for %d seconds\n", SLEEP_TIME * stry);
			(void) sleep(SLEEP_TIME * stry);
		} else {
			bam_print("WARNING: unable to sanitize HOME\n");
		}
	}
}

int
main(int argc, char *argv[])
{
	error_t ret = BAM_SUCCESS;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL) {
		prog = argv[0];
	} else {
		prog++;
	}

	INJECT_ERROR1("ASSERT_ON", assert(0))

	sanitize_env();

	parse_args(argc, argv);

	switch (bam_cmd) {
		case BAM_MENU:
			if (is_grub(bam_alt_root ? bam_root : "/")) {
				ret = bam_menu(bam_subcmd, bam_opt,
				    bam_argc, bam_argv);
			} else {
				ret = bam_loader_menu(bam_subcmd, bam_opt,
				    bam_argc, bam_argv);
			}
			break;
		case BAM_ARCHIVE:
			ret = bam_archive(bam_subcmd, bam_opt);
			break;
		case BAM_INSTALL:
			ret = bam_install(bam_subcmd, bam_opt);
			break;
		default:
			usage();
			bam_exit(1);
	}

	if (ret != BAM_SUCCESS)
		bam_exit((ret == BAM_NOCHANGE) ? 2 : 1);

	bam_unlock();
	return (0);
}

/*
 * Equivalence of public and internal commands:
 *	update-archive  -- -a update
 *	list-archive	-- -a list
 *	set-menu	-- -m set_option
 *	list-menu	-- -m list_entry
 *	update-menu	-- -m update_entry
 *	install-bootloader	-- -i install_bootloader
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
	{ "install-bootloader",	BAM_INSTALL,	"install_bootloader"},
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
 *	-a update			-- update-archive
 *	-a list				-- list-archive
 *	-a update-all			-- (reboot to sync all mnted OS archive)
 *	-i install_bootloader		-- install-bootloader
 *	-m update_entry			-- update-menu
 *	-m list_entry			-- list-menu
 *	-m update_temp			-- (reboot -- [boot-args])
 *	-m delete_all_entries		-- (called from install)
 *	-m enable_hypervisor [args]	-- cvt_to_hyper
 *	-m disable_hypervisor		-- cvt_to_metal
 *	-m list_setting [entry] [value]	-- list_setting
 *
 * A set of private flags is there too:
 *	-F		-- purge the cache directories and rebuild them
 *	-e		-- use the (faster) archive update approach (used by
 *			   reboot)
 */
static void
parse_args_internal(int argc, char *argv[])
{
	int c, error;
	extern char *optarg;
	extern int optind, opterr;
#if defined(_OBP)
	const char *optstring = "a:d:fi:m:no:veFCR:p:P:XZ";
#else
	const char *optstring = "a:d:fi:m:no:veFCMR:p:P:XZ";
#endif

	/* Suppress error message from getopt */
	opterr = 0;

	error = 0;
	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'a':
			if (bam_cmd) {
				error = 1;
				bam_error(
				    _("multiple commands specified: -%c\n"), c);
			}
			bam_cmd = BAM_ARCHIVE;
			bam_subcmd = optarg;
			break;
		case 'd':
			if (bam_debug) {
				error = 1;
				bam_error(
				    _("duplicate options specified: -%c\n"), c);
			}
			bam_debug = s_strtol(optarg);
			break;
		case 'f':
			bam_force = 1;
			break;
		case 'F':
			bam_purge = 1;
			break;
		case 'i':
			if (bam_cmd) {
				error = 1;
				bam_error(
				    _("multiple commands specified: -%c\n"), c);
			}
			bam_cmd = BAM_INSTALL;
			bam_subcmd = optarg;
			break;
		case 'm':
			if (bam_cmd) {
				error = 1;
				bam_error(
				    _("multiple commands specified: -%c\n"), c);
			}
			bam_cmd = BAM_MENU;
			bam_subcmd = optarg;
			break;
#if !defined(_OBP)
		case 'M':
			bam_mbr = 1;
			break;
#endif
		case 'n':
			bam_check = 1;
			/*
			 * We save the original value of bam_check. The new
			 * approach in case of a read-only filesystem is to
			 * behave as a check, so we need a way to restore the
			 * original value after the evaluation of the read-only
			 * filesystem has been done.
			 * Even if we don't allow at the moment a check with
			 * update_all, this approach is more robust than
			 * simply resetting bam_check to zero.
			 */
			bam_saved_check = 1;
			break;
		case 'o':
			if (bam_opt) {
				error = 1;
				bam_error(
				    _("duplicate options specified: -%c\n"), c);
			}
			bam_opt = optarg;
			break;
		case 'v':
			bam_verbose = 1;
			break;
		case 'C':
			bam_smf_check = 1;
			break;
		case 'P':
			if (bam_pool != NULL) {
				error = 1;
				bam_error(
				    _("duplicate options specified: -%c\n"), c);
			}
			bam_pool = optarg;
			break;
		case 'R':
			if (bam_root) {
				error = 1;
				bam_error(
				    _("duplicate options specified: -%c\n"), c);
				break;
			} else if (realpath(optarg, rootbuf) == NULL) {
				error = 1;
				bam_error(_("cannot resolve path %s: %s\n"),
				    optarg, strerror(errno));
				break;
			}
			bam_alt_root = 1;
			bam_root = rootbuf;
			bam_rootlen = strlen(rootbuf);
			break;
		case 'p':
			bam_alt_platform = 1;
			bam_platform = optarg;
			if ((strcmp(bam_platform, "i86pc") != 0) &&
			    (strcmp(bam_platform, "sun4u") != 0) &&
			    (strcmp(bam_platform, "sun4v") != 0)) {
				error = 1;
				bam_error(_("invalid platform %s - must be "
				    "one of sun4u, sun4v or i86pc\n"),
				    bam_platform);
			}
			break;
		case 'X':
			bam_is_hv = BAM_HV_PRESENT;
			break;
		case 'Z':
			bam_zfs = 1;
			break;
		case 'e':
			bam_extend = 1;
			break;
		case '?':
			error = 1;
			bam_error(_("invalid option or missing option "
			    "argument: -%c\n"), optopt);
			break;
		default :
			error = 1;
			bam_error(_("invalid option or missing option "
			    "argument: -%c\n"), c);
			break;
		}
	}

	/*
	 * An alternate platform requires an alternate root
	 */
	if (bam_alt_platform && bam_alt_root == 0) {
		usage();
		bam_exit(0);
	}

	/*
	 * A command option must be specfied
	 */
	if (!bam_cmd) {
		if (bam_opt && strcmp(bam_opt, "all") == 0) {
			usage();
			bam_exit(0);
		}
		bam_error(_("a command option must be specified\n"));
		error = 1;
	}

	if (error) {
		usage();
		bam_exit(1);
	}

	if (optind > argc) {
		bam_error(_("Internal error: %s\n"), "parse_args");
		bam_exit(1);
	} else if (optind < argc) {
		bam_argv = &argv[optind];
		bam_argc = argc - optind;
	}

	/*
	 * mbr and pool are options for install_bootloader
	 */
	if (bam_cmd != BAM_INSTALL && (bam_mbr || bam_pool != NULL)) {
		usage();
		bam_exit(0);
	}

	/*
	 * -n implies verbose mode
	 */
	if (bam_check)
		bam_verbose = 1;
}

error_t
check_subcmd_and_options(
	char *subcmd,
	char *opt,
	subcmd_defn_t *table,
	error_t (**fp)())
{
	int i;

	if (subcmd == NULL) {
		bam_error(_("this command requires a sub-command\n"));
		return (BAM_ERROR);
	}

	if (strcmp(subcmd, "set_option") == 0) {
		if (bam_argc == 0 || bam_argv == NULL || bam_argv[0] == NULL) {
			bam_error(_("missing argument for sub-command\n"));
			usage();
			return (BAM_ERROR);
		} else if (bam_argc > 1 || bam_argv[1] != NULL) {
			bam_error(_("invalid trailing arguments\n"));
			usage();
			return (BAM_ERROR);
		}
	} else if (strcmp(subcmd, "update_all") == 0) {
		/*
		 * The only option we accept for the "update_all"
		 * subcmd is "fastboot".
		 */
		if (bam_argc > 1 || (bam_argc == 1 &&
		    strcmp(bam_argv[0], "fastboot") != 0)) {
			bam_error(_("invalid trailing arguments\n"));
			usage();
			return (BAM_ERROR);
		}
		if (bam_argc == 1)
			sync_menu = 0;
	} else if (((strcmp(subcmd, "enable_hypervisor") != 0) &&
	    (strcmp(subcmd, "list_setting") != 0)) && (bam_argc || bam_argv)) {
		/*
		 * Of the remaining subcommands, only "enable_hypervisor" and
		 * "list_setting" take trailing arguments.
		 */
		bam_error(_("invalid trailing arguments\n"));
		usage();
		return (BAM_ERROR);
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
		bam_error(_("invalid sub-command specified: %s\n"), subcmd);
		return (BAM_ERROR);
	}

	if (table[i].unpriv == 0 && geteuid() != 0) {
		bam_error(_("you must be root to run this command\n"));
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
				bam_error(_("this sub-command (%s) does not "
				    "take options\n"), subcmd);
			else
				bam_error(_("an option is required for this "
				    "sub-command: %s\n"), subcmd);
			return (BAM_ERROR);
		}
	}

	*fp = table[i].handler;

	return (BAM_SUCCESS);
}

/*
 * NOTE: A single "/" is also considered a trailing slash and will
 * be deleted.
 */
void
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

static int
is_safe_exec(char *path)
{
	struct stat	sb;

	if (lstat(path, &sb) != 0) {
		bam_error(_("stat of file failed: %s: %s\n"), path,
		    strerror(errno));
		return (BAM_ERROR);
	}

	if (!S_ISREG(sb.st_mode)) {
		bam_error(_("%s is not a regular file, skipping\n"), path);
		return (BAM_ERROR);
	}

	if (sb.st_uid != getuid()) {
		bam_error(_("%s is not owned by %d, skipping\n"),
		    path, getuid());
		return (BAM_ERROR);
	}

	if (sb.st_mode & S_IWOTH || sb.st_mode & S_IWGRP) {
		bam_error(_("%s is others or group writable, skipping\n"),
		    path);
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

static error_t
list_setting(menu_t *mp, char *which, char *setting)
{
	line_t	*lp;
	entry_t	*ent;

	char	*p = which;
	int	entry;

	int	found;

	assert(which);
	assert(setting);

	if (*which != NULL) {
		/*
		 * If "which" is not a number, assume it's a setting we want
		 * to look for and so set up the routine to look for "which"
		 * in the default entry.
		 */
		while (*p != NULL)
			if (!(isdigit((int)*p++))) {
				setting = which;
				which = mp->curdefault->arg;
				break;
			}
	} else {
		which = mp->curdefault->arg;
	}

	entry = atoi(which);

	for (ent = mp->entries; ((ent != NULL) && (ent->entryNum != entry));
	    ent = ent->next)
		;

	if (!ent) {
		bam_error(_("no matching entry found\n"));
		return (BAM_ERROR);
	}

	found = (*setting == NULL);

	for (lp = ent->start; lp != NULL; lp = lp->next) {
		if ((*setting == NULL) && (lp->flags != BAM_COMMENT))
			bam_print("%s\n", lp->line);
		else if (lp->cmd != NULL && strcmp(setting, lp->cmd) == 0) {
			bam_print("%s\n", lp->arg);
			found = 1;
		}

		if (lp == ent->end)
			break;
	}

	if (!found) {
		bam_error(_("no matching entry found\n"));
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

static error_t
install_bootloader(void)
{
	nvlist_t	*nvl;
	uint16_t	flags = 0;
	int		found = 0;
	struct extmnttab mnt;
	struct stat	statbuf = {0};
	be_node_list_t	*be_nodes, *node;
	FILE		*fp;
	char		*root_ds = NULL;
	int		ret = BAM_ERROR;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		bam_error(_("out of memory\n"));
		return (ret);
	}

	/*
	 * if bam_alt_root is set, the stage files are used from alt root.
	 * if pool is set, the target devices are pool devices, stage files
	 * are read from pool bootfs unless alt root is set.
	 *
	 * use arguments as targets, stage files are from alt or current root
	 * if no arguments and no pool, install on current boot pool.
	 */

	if (bam_alt_root) {
		if (stat(bam_root, &statbuf) != 0) {
			bam_error(_("stat of file failed: %s: %s\n"), bam_root,
			    strerror(errno));
			goto done;
		}
		if ((fp = fopen(MNTTAB, "r")) == NULL) {
			bam_error(_("failed to open file: %s: %s\n"),
			    MNTTAB, strerror(errno));
			goto done;
		}
		resetmnttab(fp);
		while (getextmntent(fp, &mnt, sizeof (mnt)) == 0) {
			if (mnt.mnt_major == major(statbuf.st_dev) &&
			    mnt.mnt_minor == minor(statbuf.st_dev)) {
				found = 1;
				root_ds = strdup(mnt.mnt_special);
				break;
			}
		}
		(void) fclose(fp);

		if (found == 0) {
			bam_error(_("alternate root %s not in mnttab\n"),
			    bam_root);
			goto done;
		}
		if (root_ds == NULL) {
			bam_error(_("out of memory\n"));
			goto done;
		}

		if (be_list(NULL, &be_nodes) != BE_SUCCESS) {
			bam_error(_("No BE's found\n"));
			goto done;
		}
		for (node = be_nodes; node != NULL; node = node->be_next_node)
			if (strcmp(root_ds, node->be_root_ds) == 0)
				break;

		if (node == NULL)
			bam_error(_("BE (%s) does not exist\n"), root_ds);

		free(root_ds);
		root_ds = NULL;
		if (node == NULL) {
			be_free_list(be_nodes);
			goto done;
		}
		ret = nvlist_add_string(nvl, BE_ATTR_ORIG_BE_NAME,
		    node->be_node_name);
		ret |= nvlist_add_string(nvl, BE_ATTR_ORIG_BE_ROOT,
		    node->be_root_ds);
		be_free_list(be_nodes);
		if (ret != 0) {
			ret = BAM_ERROR;
			goto done;
		}
	}

	if (bam_force)
		flags |= BE_INSTALLBOOT_FLAG_FORCE;
	if (bam_mbr)
		flags |= BE_INSTALLBOOT_FLAG_MBR;
	if (bam_verbose)
		flags |= BE_INSTALLBOOT_FLAG_VERBOSE;

	if (nvlist_add_uint16(nvl, BE_ATTR_INSTALL_FLAGS, flags) != 0) {
		bam_error(_("out of memory\n"));
		ret = BAM_ERROR;
		goto done;
	}

	/*
	 * if altroot was set, we got be name and be root, only need
	 * to set pool name as target.
	 * if no altroot, need to find be name and root from pool.
	 */
	if (bam_pool != NULL) {
		ret = nvlist_add_string(nvl, BE_ATTR_ORIG_BE_POOL, bam_pool);
		if (ret != 0) {
			ret = BAM_ERROR;
			goto done;
		}
		if (found) {
			ret = be_installboot(nvl);
			if (ret != 0)
				ret = BAM_ERROR;
			goto done;
		}
	}

	if (be_list(NULL, &be_nodes) != BE_SUCCESS) {
		bam_error(_("No BE's found\n"));
		ret = BAM_ERROR;
		goto done;
	}

	if (bam_pool != NULL) {
		/*
		 * find active be_node in bam_pool
		 */
		for (node = be_nodes; node != NULL; node = node->be_next_node) {
			if (strcmp(bam_pool, node->be_rpool) != 0)
				continue;
			if (node->be_active_on_boot)
				break;
		}
		if (node == NULL) {
			bam_error(_("No active BE in %s\n"), bam_pool);
			be_free_list(be_nodes);
			ret = BAM_ERROR;
			goto done;
		}
		ret = nvlist_add_string(nvl, BE_ATTR_ORIG_BE_NAME,
		    node->be_node_name);
		ret |= nvlist_add_string(nvl, BE_ATTR_ORIG_BE_ROOT,
		    node->be_root_ds);
		be_free_list(be_nodes);
		if (ret != 0) {
			ret = BAM_ERROR;
			goto done;
		}
		ret = be_installboot(nvl);
		if (ret != 0)
			ret = BAM_ERROR;
		goto done;
	}

	/*
	 * get dataset for "/" and fill up the args.
	 */
	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		bam_error(_("failed to open file: %s: %s\n"),
		    MNTTAB, strerror(errno));
		ret = BAM_ERROR;
		be_free_list(be_nodes);
		goto done;
	}
	resetmnttab(fp);
	found = 0;
	while (getextmntent(fp, &mnt, sizeof (mnt)) == 0) {
		if (strcmp(mnt.mnt_mountp, "/") == 0) {
			found = 1;
			root_ds = strdup(mnt.mnt_special);
			break;
		}
	}
	(void) fclose(fp);

	if (found == 0) {
		bam_error(_("alternate root %s not in mnttab\n"), "/");
		ret = BAM_ERROR;
		be_free_list(be_nodes);
		goto done;
	}
	if (root_ds == NULL) {
		bam_error(_("out of memory\n"));
		ret = BAM_ERROR;
		be_free_list(be_nodes);
		goto done;
	}

	for (node = be_nodes; node != NULL; node = node->be_next_node) {
		if (strcmp(root_ds, node->be_root_ds) == 0)
			break;
	}

	if (node == NULL) {
		bam_error(_("No such BE: %s\n"), root_ds);
		free(root_ds);
		be_free_list(be_nodes);
		ret = BAM_ERROR;
		goto done;
	}
	free(root_ds);

	ret = nvlist_add_string(nvl, BE_ATTR_ORIG_BE_NAME, node->be_node_name);
	ret |= nvlist_add_string(nvl, BE_ATTR_ORIG_BE_ROOT, node->be_root_ds);
	ret |= nvlist_add_string(nvl, BE_ATTR_ORIG_BE_POOL, node->be_rpool);
	be_free_list(be_nodes);

	if (ret != 0)
		ret = BAM_ERROR;
	else
		ret = be_installboot(nvl) ? BAM_ERROR : 0;
done:
	nvlist_free(nvl);

	return (ret);
}

static error_t
bam_install(char *subcmd, char *opt)
{
	error_t (*f)(void);

	/*
	 * Check arguments
	 */
	if (check_subcmd_and_options(subcmd, opt, inst_subcmds, &f) ==
	    BAM_ERROR)
		return (BAM_ERROR);

	return (f());
}

static error_t
bam_menu(char *subcmd, char *opt, int largc, char *largv[])
{
	error_t			ret;
	char			menu_path[PATH_MAX];
	char			clean_menu_root[PATH_MAX];
	char			path[PATH_MAX];
	menu_t			*menu;
	char			menu_root[PATH_MAX];
	struct stat		sb;
	error_t (*f)(menu_t *mp, char *menu_path, char *opt);
	char			*special = NULL;
	char			*pool = NULL;
	zfs_mnted_t		zmnted;
	char			*zmntpt = NULL;
	char			*osdev;
	char			*osroot;
	const char		*fcn = "bam_menu()";

	/*
	 * Menu sub-command only applies to GRUB (i.e. x86)
	 */
	if (!is_grub(bam_alt_root ? bam_root : "/")) {
		bam_error(_("not a GRUB 0.97 based Illumos instance. "
		    "Operation not supported\n"));
		return (BAM_ERROR);
	}

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

	/*
	 * We support menu on PCFS (under certain conditions), but
	 * not the OS root
	 */
	if (is_pcfs(bam_root)) {
		bam_error(_("root <%s> on PCFS is not supported\n"), bam_root);
		return (BAM_ERROR);
	}

	if (stat(menu_root, &sb) == -1) {
		bam_error(_("cannot find GRUB menu\n"));
		return (BAM_ERROR);
	}

	BAM_DPRINTF(("%s: menu root is %s\n", fcn, menu_root));

	/*
	 * We no longer use the GRUB slice file. If it exists, then
	 * the user is doing something that is unsupported (such as
	 * standard upgrading an old Live Upgrade BE). If that
	 * happens, mimic existing behavior i.e. pretend that it is
	 * not a BE. Emit a warning though.
	 */
	if (bam_alt_root) {
		(void) snprintf(path, sizeof (path), "%s%s", bam_root,
		    GRUB_slice);
	} else {
		(void) snprintf(path, sizeof (path), "%s", GRUB_slice);
	}

	if (bam_verbose && stat(path, &sb) == 0)
		bam_error(_("unsupported GRUB slice file (%s) exists - "
		    "ignoring.\n"), path);

	if (is_zfs(menu_root)) {
		assert(strcmp(menu_root, bam_root) == 0);
		special = get_special(menu_root);
		INJECT_ERROR1("Z_MENU_GET_SPECIAL", special = NULL);
		if (special == NULL) {
			bam_error(_("cant find special file for "
			    "mount-point %s\n"), menu_root);
			return (BAM_ERROR);
		}
		pool = strtok(special, "/");
		INJECT_ERROR1("Z_MENU_GET_POOL", pool = NULL);
		if (pool == NULL) {
			free(special);
			bam_error(_("cant find pool for mount-point %s\n"),
			    menu_root);
			return (BAM_ERROR);
		}
		BAM_DPRINTF(("%s: derived pool=%s from special\n", fcn, pool));

		zmntpt = mount_top_dataset(pool, &zmnted);
		INJECT_ERROR1("Z_MENU_MOUNT_TOP_DATASET", zmntpt = NULL);
		if (zmntpt == NULL) {
			bam_error(_("cannot mount pool dataset for pool: %s\n"),
			    pool);
			free(special);
			return (BAM_ERROR);
		}
		BAM_DPRINTF(("%s: top dataset mountpoint=%s\n", fcn, zmntpt));

		(void) strlcpy(menu_root, zmntpt, sizeof (menu_root));
		BAM_DPRINTF(("%s: zfs menu_root=%s\n", fcn, menu_root));
	}

	elide_trailing_slash(menu_root, clean_menu_root,
	    sizeof (clean_menu_root));

	BAM_DPRINTF(("%s: cleaned menu root is <%s>\n", fcn, clean_menu_root));

	(void) strlcpy(menu_path, clean_menu_root, sizeof (menu_path));
	(void) strlcat(menu_path, GRUB_MENU, sizeof (menu_path));

	BAM_DPRINTF(("%s: menu path is: %s\n", fcn, menu_path));

	/*
	 * If listing the menu, display the menu location
	 */
	if (strcmp(subcmd, "list_entry") == 0)
		bam_print(_("the location for the active GRUB menu is: %s\n"),
		    menu_path);

	if ((menu = menu_read(menu_path)) == NULL) {
		bam_error(_("cannot find GRUB menu file: %s\n"), menu_path);
		free(special);

		return (BAM_ERROR);
	}

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

	ret = get_boot_cap(bam_root);
	if (ret != BAM_SUCCESS) {
		BAM_DPRINTF(("%s: Failed to get boot capability\n", fcn));
		goto out;
	}

	/*
	 * Once the sub-cmd handler has run
	 * only the line field is guaranteed to have valid values
	 */
	if (strcmp(subcmd, "update_entry") == 0) {
		ret = f(menu, menu_root, osdev);
	} else if (strcmp(subcmd, "upgrade") == 0) {
		ret = f(menu, bam_root, menu_root);
	} else if (strcmp(subcmd, "list_entry") == 0) {
		ret = f(menu, menu_path, opt);
	} else if (strcmp(subcmd, "list_setting") == 0) {
		ret = f(menu, ((largc > 0) ? largv[0] : ""),
		    ((largc > 1) ? largv[1] : ""));
	} else if (strcmp(subcmd, "disable_hypervisor") == 0) {
		if (is_sparc()) {
			bam_error(_("%s operation unsupported on SPARC "
			    "machines\n"), subcmd);
			ret = BAM_ERROR;
		} else {
			ret = f(menu, bam_root, NULL);
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

			ret = f(menu, bam_root, extra_args);
		}
	} else
		ret = f(menu, NULL, opt);

	if (ret == BAM_WRITE) {
		BAM_DPRINTF(("%s: writing menu to clean-menu-root: <%s>\n",
		    fcn, clean_menu_root));
		ret = menu_write(clean_menu_root, menu);
	}

out:
	INJECT_ERROR1("POOL_SET", pool = "/pooldata");
	assert((is_zfs(menu_root)) ^ (pool == NULL));
	if (pool) {
		(void) umount_top_dataset(pool, zmnted, zmntpt);
		free(special);
	}
	menu_free(menu);
	return (ret);
}


static error_t
bam_archive(
	char *subcmd,
	char *opt)
{
	error_t			ret;
	error_t			(*f)(char *root, char *opt);
	const char		*fcn = "bam_archive()";

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

	ret = get_boot_cap(rootbuf);
	if (ret != BAM_SUCCESS) {
		BAM_DPRINTF(("%s: Failed to get boot capability\n", fcn));
		return (ret);
	}

	/*
	 * Check archive not supported with update_all
	 * since it is awkward to display out-of-sync
	 * information for each BE.
	 */
	if (bam_check && strcmp(subcmd, "update_all") == 0) {
		bam_error(_("the check option is not supported with "
		    "subcmd: %s\n"), subcmd);
		return (BAM_ERROR);
	}

	if (strcmp(subcmd, "update_all") == 0)
		bam_update_all = 1;

#if !defined(_OBP)
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
void
bam_derror(char *format, ...)
{
	va_list ap;

	assert(bam_debug);

	va_start(ap, format);
	(void) fprintf(stderr, "DEBUG: ");
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
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

void
bam_exit(int excode)
{
	restore_env();
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

		bam_error(_("failed to open file: %s: %s\n"),
		    BAM_LOCK_FILE, strerror(errno));
		bam_exit(1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(bam_lock_fd, F_SETLK, &lock) == -1) {
		if (errno != EACCES && errno != EAGAIN) {
			bam_error(_("failed to lock file: %s: %s\n"),
			    BAM_LOCK_FILE, strerror(errno));
			(void) close(bam_lock_fd);
			bam_lock_fd = -1;
			bam_exit(1);
		}
		pid = 0;
		(void) pread(bam_lock_fd, &pid, sizeof (pid_t), 0);
		bam_print(
		    _("another instance of bootadm (pid %lu) is running\n"),
		    pid);

		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;
		lock.l_len = 0;
		if (fcntl(bam_lock_fd, F_SETLKW, &lock) == -1) {
			bam_error(_("failed to lock file: %s: %s\n"),
			    BAM_LOCK_FILE, strerror(errno));
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
		bam_error(_("failed to unlock file: %s: %s\n"),
		    BAM_LOCK_FILE, strerror(errno));
	}

	if (close(bam_lock_fd) == -1) {
		bam_error(_("failed to close file: %s: %s\n"),
		    BAM_LOCK_FILE, strerror(errno));
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
		bam_print(_("%s\n"), lp->line);
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
	char		tmpfile[PATH_MAX];
	char		path[PATH_MAX];
	FILE		*fp;
	int		ret;
	struct stat	sb;
	mode_t		mode;
	uid_t		root_uid;
	gid_t		sys_gid;
	struct passwd	*pw;
	struct group	*gp;
	const char	*fcn = "list2file()";

	(void) snprintf(path, sizeof (path), "%s%s", root, final);

	if (start == NULL) {
		/* Empty GRUB menu */
		if (stat(path, &sb) != -1) {
			bam_print(_("file is empty, deleting file: %s\n"),
			    path);
			if (unlink(path) != 0) {
				bam_error(_("failed to unlink file: %s: %s\n"),
				    path, strerror(errno));
				return (BAM_ERROR);
			} else {
				return (BAM_SUCCESS);
			}
		}
		return (BAM_SUCCESS);
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
			bam_error(_("getpwnam: uid for %s failed, "
			    "defaulting to %d\n"),
			    DEFAULT_DEV_USER, DEFAULT_DEV_UID);
			root_uid = (uid_t)DEFAULT_DEV_UID;
		}
		if ((gp = getgrnam(DEFAULT_DEV_GROUP)) != NULL) {
			sys_gid = gp->gr_gid;
		} else {
			bam_error(_("getgrnam: gid for %s failed, "
			    "defaulting to %d\n"),
			    DEFAULT_DEV_GROUP, DEFAULT_DEV_GID);
			sys_gid = (gid_t)DEFAULT_DEV_GID;
		}
	}

	(void) snprintf(tmpfile, sizeof (tmpfile), "%s%s", root, tmp);

	/* Truncate tmpfile first */
	fp = fopen(tmpfile, "w");
	if (fp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"), tmpfile,
		    strerror(errno));
		return (BAM_ERROR);
	}
	ret = fclose(fp);
	INJECT_ERROR1("LIST2FILE_TRUNC_FCLOSE", ret = EOF);
	if (ret == EOF) {
		bam_error(_("failed to close file: %s: %s\n"),
		    tmpfile, strerror(errno));
		return (BAM_ERROR);
	}

	/* Now open it in append mode */
	fp = fopen(tmpfile, "a");
	if (fp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"), tmpfile,
		    strerror(errno));
		return (BAM_ERROR);
	}

	for (; start; start = start->next) {
		ret = s_fputs(start->line, fp);
		INJECT_ERROR1("LIST2FILE_FPUTS", ret = EOF);
		if (ret == EOF) {
			bam_error(_("write to file failed: %s: %s\n"),
			    tmpfile, strerror(errno));
			(void) fclose(fp);
			return (BAM_ERROR);
		}
	}

	ret = fclose(fp);
	INJECT_ERROR1("LIST2FILE_APPEND_FCLOSE", ret = EOF);
	if (ret == EOF) {
		bam_error(_("failed to close file: %s: %s\n"),
		    tmpfile, strerror(errno));
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
		bam_error(_("chmod operation on %s failed - %s\n"),
		    tmpfile, strerror(errno));
		return (BAM_ERROR);
	}

	ret = chown(tmpfile, root_uid, sys_gid);
	if (ret == -1 &&
	    errno != EINVAL && errno != ENOTSUP) {
		bam_error(_("chgrp operation on %s failed - %s\n"),
		    tmpfile, strerror(errno));
		return (BAM_ERROR);
	}

	/*
	 * Do an atomic rename
	 */
	ret = rename(tmpfile, path);
	INJECT_ERROR1("LIST2FILE_RENAME", ret = -1);
	if (ret != 0) {
		bam_error(_("rename to file failed: %s: %s\n"), path,
		    strerror(errno));
		return (BAM_ERROR);
	}

	BAM_DPRINTF(("%s: wrote file successfully: %s\n", fcn, path));
	return (BAM_SUCCESS);
}

/*
 * Checks if the path specified (without the file name at the end) exists
 * and creates it if not. If the path exists and is not a directory, an attempt
 * to unlink is made.
 */
static int
setup_path(char *path)
{
	char 		*p;
	int		ret;
	struct stat	sb;

	p = strrchr(path, '/');
	if (p != NULL) {
		*p = '\0';
		if (stat(path, &sb) != 0 || !(S_ISDIR(sb.st_mode))) {
			/* best effort attempt, mkdirp will catch the error */
			(void) unlink(path);
			if (bam_verbose)
				bam_print(_("need to create directory "
				    "path for %s\n"), path);
			ret = mkdirp(path, DIR_PERMS);
			if (ret == -1) {
				bam_error(_("mkdir of %s failed: %s\n"),
				    path, strerror(errno));
				*p = '/';
				return (BAM_ERROR);
			}
		}
		*p = '/';
		return (BAM_SUCCESS);
	}
	return (BAM_SUCCESS);
}

typedef union {
	gzFile	gzfile;
	int	fdfile;
} outfile;

typedef struct {
	char		path[PATH_MAX];
	outfile		out;
} cachefile;

static int
setup_file(char *base, const char *path, cachefile *cf)
{
	int	ret;
	char	*strip;

	/* init gzfile or fdfile in case we fail before opening */
	if (bam_direct == BAM_DIRECT_DBOOT)
		cf->out.gzfile = NULL;
	else
		cf->out.fdfile = -1;

	/* strip the trailing altroot path */
	strip = (char *)path + strlen(rootbuf);

	ret = snprintf(cf->path, sizeof (cf->path), "%s/%s", base, strip);
	if (ret >= sizeof (cf->path)) {
		bam_error(_("unable to create path on mountpoint %s, "
		    "path too long\n"), rootbuf);
		return (BAM_ERROR);
	}

	/* Check if path is present in the archive cache directory */
	if (setup_path(cf->path) == BAM_ERROR)
		return (BAM_ERROR);

	if (bam_direct == BAM_DIRECT_DBOOT) {
		if ((cf->out.gzfile = gzopen(cf->path, "wb")) == NULL) {
			bam_error(_("failed to open file: %s: %s\n"),
			    cf->path, strerror(errno));
			return (BAM_ERROR);
		}
		(void) gzsetparams(cf->out.gzfile, Z_BEST_SPEED,
		    Z_DEFAULT_STRATEGY);
	} else {
		if ((cf->out.fdfile = open(cf->path, O_WRONLY | O_CREAT, 0644))
		    == -1) {
			bam_error(_("failed to open file: %s: %s\n"),
			    cf->path, strerror(errno));
			return (BAM_ERROR);
		}
	}

	return (BAM_SUCCESS);
}

static int
cache_write(cachefile cf, char *buf, int size)
{
	int	err;

	if (bam_direct == BAM_DIRECT_DBOOT) {
		if (gzwrite(cf.out.gzfile, buf, size) < 1) {
			bam_error(_("failed to write to %s\n"),
			    gzerror(cf.out.gzfile, &err));
			if (err == Z_ERRNO && bam_verbose) {
				bam_error(_("write to file failed: %s: %s\n"),
				    cf.path, strerror(errno));
			}
			return (BAM_ERROR);
		}
	} else {
		if (write(cf.out.fdfile, buf, size) < 1) {
			bam_error(_("write to file failed: %s: %s\n"),
			    cf.path, strerror(errno));
			return (BAM_ERROR);
		}
	}
	return (BAM_SUCCESS);
}

static int
cache_close(cachefile cf)
{
	int	ret;

	if (bam_direct == BAM_DIRECT_DBOOT) {
		if (cf.out.gzfile) {
			ret = gzclose(cf.out.gzfile);
			if (ret != Z_OK) {
				bam_error(_("failed to close file: %s: %s\n"),
				    cf.path, strerror(errno));
				return (BAM_ERROR);
			}
		}
	} else {
		if (cf.out.fdfile != -1) {
			ret = close(cf.out.fdfile);
			if (ret != 0) {
				bam_error(_("failed to close file: %s: %s\n"),
				    cf.path, strerror(errno));
				return (BAM_ERROR);
			}
		}
	}

	return (BAM_SUCCESS);
}

static int
dircache_updatefile(const char *path, int what)
{
	int 		ret, exitcode;
	char 		buf[4096 * 4];
	FILE 		*infile;
	cachefile 	outfile, outupdt;

	if (bam_nowrite()) {
		set_dir_flag(what, NEED_UPDATE);
		return (BAM_SUCCESS);
	}

	if (!has_cachedir(what))
		return (BAM_SUCCESS);

	if ((infile = fopen(path, "rb")) == NULL) {
		bam_error(_("failed to open file: %s: %s\n"), path,
		    strerror(errno));
		return (BAM_ERROR);
	}

	ret = setup_file(get_cachedir(what), path, &outfile);
	if (ret == BAM_ERROR) {
		exitcode = BAM_ERROR;
		goto out;
	}
	if (!is_dir_flag_on(what, NO_MULTI)) {
		ret = setup_file(get_updatedir(what), path, &outupdt);
		if (ret == BAM_ERROR)
			set_dir_flag(what, NO_MULTI);
	}

	while ((ret = fread(buf, 1, sizeof (buf), infile)) > 0) {
		if (cache_write(outfile, buf, ret) == BAM_ERROR) {
			exitcode = BAM_ERROR;
			goto out;
		}
		if (!is_dir_flag_on(what, NO_MULTI))
			if (cache_write(outupdt, buf, ret) == BAM_ERROR)
				set_dir_flag(what, NO_MULTI);
	}

	set_dir_flag(what, NEED_UPDATE);
	get_count(what)++;
	if (get_count(what) > COUNT_MAX)
		set_dir_flag(what, NO_MULTI);
	exitcode = BAM_SUCCESS;
out:
	(void) fclose(infile);
	if (cache_close(outfile) == BAM_ERROR)
		exitcode = BAM_ERROR;
	if (!is_dir_flag_on(what, NO_MULTI) &&
	    cache_close(outupdt) == BAM_ERROR)
		exitcode = BAM_ERROR;
	if (exitcode == BAM_ERROR)
		set_flag(UPDATE_ERROR);
	return (exitcode);
}

static int
dircache_updatedir(const char *path, int what, int updt)
{
	int		ret;
	char		dpath[PATH_MAX];
	char		*strip;
	struct stat	sb;

	strip = (char *)path + strlen(rootbuf);

	ret = snprintf(dpath, sizeof (dpath), "%s/%s", updt ?
	    get_updatedir(what) : get_cachedir(what), strip);

	if (ret >= sizeof (dpath)) {
		bam_error(_("unable to create path on mountpoint %s, "
		    "path too long\n"), rootbuf);
		set_flag(UPDATE_ERROR);
		return (BAM_ERROR);
	}

	if (stat(dpath, &sb) == 0 && S_ISDIR(sb.st_mode))
		return (BAM_SUCCESS);

	if (updt) {
		if (!is_dir_flag_on(what, NO_MULTI))
			if (!bam_nowrite() && mkdirp(dpath, DIR_PERMS) == -1)
				set_dir_flag(what, NO_MULTI);
	} else {
		if (!bam_nowrite() && mkdirp(dpath, DIR_PERMS) == -1) {
			set_flag(UPDATE_ERROR);
			return (BAM_ERROR);
		}
	}

	set_dir_flag(what, NEED_UPDATE);
	return (BAM_SUCCESS);
}

#define	DO_CACHE_DIR	0
#define	DO_UPDATE_DIR	1

#if defined(_LP64) || defined(_LONGLONG_TYPE)
typedef		Elf64_Ehdr	_elfhdr;
#else
typedef		Elf32_Ehdr	_elfhdr;
#endif

/*
 * This routine updates the contents of the cache directory
 */
static int
update_dircache(const char *path, int flags)
{
	int rc = BAM_SUCCESS;

	switch (flags) {
	case FTW_F:
		{
		int	fd;
		_elfhdr	elf;

		if ((fd = open(path, O_RDONLY)) < 0) {
			bam_error(_("failed to open file: %s: %s\n"),
			    path, strerror(errno));
			set_flag(UPDATE_ERROR);
			rc = BAM_ERROR;
			break;
		}

		/*
		 * libelf and gelf would be a cleaner and easier way to handle
		 * this, but libelf fails compilation if _ILP32 is defined &&
		 * _FILE_OFFSET_BITS is != 32 ...
		 */
		if (read(fd, (void *)&elf, sizeof (_elfhdr)) < 0) {
			bam_error(_("read failed for file: %s: %s\n"),
			    path, strerror(errno));
			set_flag(UPDATE_ERROR);
			(void) close(fd);
			rc = BAM_ERROR;
			break;
		}
		(void) close(fd);

		/*
		 * If the file is not an executable and is not inside an amd64
		 * directory, we copy it in both the cache directories,
		 * otherwise, we only copy it inside the 64-bit one.
		 */
		if (memcmp(elf.e_ident, ELFMAG, 4) != 0) {
			if (strstr(path, "/amd64")) {
				rc = dircache_updatefile(path, FILE64);
			} else {
				rc = dircache_updatefile(path, FILE32);
				if (rc == BAM_SUCCESS)
					rc = dircache_updatefile(path, FILE64);
			}
		} else {
			/*
			 * Based on the ELF class we copy the file in the 32-bit
			 * or the 64-bit cache directory.
			 */
			if (elf.e_ident[EI_CLASS] == ELFCLASS32) {
				rc = dircache_updatefile(path, FILE32);
			} else if (elf.e_ident[EI_CLASS] == ELFCLASS64) {
				rc = dircache_updatefile(path, FILE64);
			} else {
				bam_print(_("WARNING: file %s is neither a "
				    "32-bit nor a 64-bit ELF\n"), path);
				/* paranoid */
				rc  = dircache_updatefile(path, FILE32);
				if (rc == BAM_SUCCESS)
					rc = dircache_updatefile(path, FILE64);
			}
		}
		break;
		}
	case FTW_D:
		if (strstr(path, "/amd64") == NULL) {
			rc = dircache_updatedir(path, FILE32, DO_UPDATE_DIR);
			if (rc == BAM_SUCCESS)
				rc = dircache_updatedir(path, FILE32,
				    DO_CACHE_DIR);
		} else {
			if (has_cachedir(FILE64)) {
				rc = dircache_updatedir(path, FILE64,
				    DO_UPDATE_DIR);
				if (rc == BAM_SUCCESS)
					rc = dircache_updatedir(path, FILE64,
					    DO_CACHE_DIR);
			}
		}
		break;
	default:
		rc = BAM_ERROR;
		break;
	}

	return (rc);
}

/*ARGSUSED*/
static int
cmpstat(
	const char *file,
	const struct stat *st,
	int flags,
	struct FTW *ftw)
{
	uint_t 		sz;
	uint64_t 	*value;
	uint64_t 	filestat[2];
	int 		error, ret, status;

	struct safefile *safefilep;
	FILE 		*fp;
	struct stat	sb;
	regex_t re;

	/*
	 * On SPARC we create/update links too.
	 */
	if (flags != FTW_F && flags != FTW_D && (flags == FTW_SL &&
	    !is_flag_on(IS_SPARC_TARGET)))
		return (0);

	/*
	 * Ignore broken links
	 */
	if (flags == FTW_SL && stat(file, &sb) < 0)
		return (0);

	/*
	 * new_nvlp may be NULL if there were errors earlier
	 * but this is not fatal to update determination.
	 */
	if (walk_arg.new_nvlp) {
		filestat[0] = st->st_size;
		filestat[1] = st->st_mtime;
		error = nvlist_add_uint64_array(walk_arg.new_nvlp,
		    file + bam_rootlen, filestat, 2);
		if (error)
			bam_error(_("failed to update stat data for: %s: %s\n"),
			    file, strerror(error));
	}

	/*
	 * If we are invoked as part of system/filesystem/boot-archive, then
	 * there are a number of things we should not worry about
	 */
	if (bam_smf_check) {
		/* ignore amd64 modules unless we are booted amd64. */
		if (!is_amd64() && strstr(file, "/amd64/") != 0)
			return (0);

		/* read in list of safe files */
		if (safefiles == NULL) {
			fp = fopen("/boot/solaris/filelist.safe", "r");
			if (fp != NULL) {
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
	}

	/*
	 * On SPARC we create a -path-list file for mkisofs
	 */
	if (is_flag_on(IS_SPARC_TARGET) && !bam_nowrite()) {
		if (flags != FTW_D) {
			char	*strip;

			strip = (char *)file + strlen(rootbuf);
			(void) fprintf(walk_arg.sparcfile, "/%s=%s\n", strip,
			    file);
		}
	}

	/*
	 * We are transitioning from the old model to the dircache or the cache
	 * directory was removed: create the entry without further checkings.
	 */
	if (is_flag_on(NEED_CACHE_DIR)) {
		if (bam_verbose)
			bam_print(_("    new     %s\n"), file);

		if (is_flag_on(IS_SPARC_TARGET)) {
			set_dir_flag(FILE64, NEED_UPDATE);
			return (0);
		}

		ret = update_dircache(file, flags);
		if (ret == BAM_ERROR) {
			bam_error(_("directory cache update failed for %s\n"),
			    file);
			return (-1);
		}

		return (0);
	}

	/*
	 * We need an update if file doesn't exist in old archive
	 */
	if (walk_arg.old_nvlp == NULL ||
	    nvlist_lookup_uint64_array(walk_arg.old_nvlp,
	    file + bam_rootlen, &value, &sz) != 0) {
		if (bam_smf_check)	/* ignore new during smf check */
			return (0);

		if (is_flag_on(IS_SPARC_TARGET)) {
			set_dir_flag(FILE64, NEED_UPDATE);
		} else {
			ret = update_dircache(file, flags);
			if (ret == BAM_ERROR) {
				bam_error(_("directory cache update "
				    "failed for %s\n"), file);
				return (-1);
			}
		}

		if (bam_verbose)
			bam_print(_("    new     %s\n"), file);
		return (0);
	}

	/*
	 * If we got there, the file is already listed as to be included in the
	 * iso image. We just need to know if we are going to rebuild it or not
	 */
	if (is_flag_on(IS_SPARC_TARGET) &&
	    is_dir_flag_on(FILE64, NEED_UPDATE) && !bam_nowrite())
		return (0);
	/*
	 * File exists in old archive. Check if file has changed
	 */
	assert(sz == 2);
	bcopy(value, filestat, sizeof (filestat));

	if (flags != FTW_D && (filestat[0] != st->st_size ||
	    filestat[1] != st->st_mtime)) {
		if (bam_smf_check) {
			safefilep = safefiles;
			while (safefilep != NULL &&
			    safefilep->name[0] != '\0') {
				if (regcomp(&re, safefilep->name,
				    REG_EXTENDED|REG_NOSUB) == 0) {
					status = regexec(&re,
					    file + bam_rootlen, 0, NULL, 0);
					regfree(&re);
					if (status == 0) {
						(void) creat(
						    NEED_UPDATE_SAFE_FILE,
						    0644);
						return (0);
					}
				}
				safefilep = safefilep->next;
			}
		}

		if (is_flag_on(IS_SPARC_TARGET)) {
			set_dir_flag(FILE64, NEED_UPDATE);
		} else {
			ret = update_dircache(file, flags);
			if (ret == BAM_ERROR) {
				bam_error(_("directory cache update failed "
				    "for %s\n"), file);
				return (-1);
			}
		}

		if (bam_verbose) {
			if (bam_smf_check)
				bam_print("    %s\n", file);
			else
				bam_print(_("    changed %s\n"), file);
		}
	}

	return (0);
}

/*
 * Remove a directory path recursively
 */
static int
rmdir_r(char *path)
{
	struct dirent 	*d = NULL;
	DIR 		*dir = NULL;
	char 		tpath[PATH_MAX];
	struct stat 	sb;

	if ((dir = opendir(path)) == NULL)
		return (-1);

	while ((d = readdir(dir)) != NULL) {
		if ((strcmp(d->d_name, ".") != 0) &&
		    (strcmp(d->d_name, "..") != 0)) {
			(void) snprintf(tpath, sizeof (tpath), "%s/%s",
			    path, d->d_name);
			if (stat(tpath, &sb) == 0) {
				if (sb.st_mode & S_IFDIR)
					(void) rmdir_r(tpath);
				else
					(void) remove(tpath);
			}
		}
	}
	return (remove(path));
}

/*
 * Check if cache directory exists and, if not, create it and update flags
 * accordingly. If the path exists, but it's not a directory, a best effort
 * attempt to remove and recreate it is made.
 * If the user requested a 'purge', always recreate the directory from scratch.
 */
static int
set_cache_dir(char *root, int what)
{
	struct stat	sb;
	int		ret = 0;

	ret = snprintf(get_cachedir(what), sizeof (get_cachedir(what)),
	    "%s%s%s%s%s", root, ARCHIVE_PREFIX, get_machine(), what == FILE64 ?
	    "/amd64" : "", CACHEDIR_SUFFIX);

	if (ret >= sizeof (get_cachedir(what))) {
		bam_error(_("unable to create path on mountpoint %s, "
		    "path too long\n"), rootbuf);
		return (BAM_ERROR);
	}

	if (bam_purge || is_flag_on(INVALIDATE_CACHE))
		(void) rmdir_r(get_cachedir(what));

	if (stat(get_cachedir(what), &sb) != 0 || !(S_ISDIR(sb.st_mode))) {
		/* best effort unlink attempt, mkdir will catch errors */
		(void) unlink(get_cachedir(what));

		if (bam_verbose)
			bam_print(_("archive cache directory not found: %s\n"),
			    get_cachedir(what));
		ret = mkdir(get_cachedir(what), DIR_PERMS);
		if (ret < 0) {
			bam_error(_("mkdir of %s failed: %s\n"),
			    get_cachedir(what), strerror(errno));
			get_cachedir(what)[0] = '\0';
			return (ret);
		}
		set_flag(NEED_CACHE_DIR);
		set_dir_flag(what, NO_MULTI);
	}

	return (BAM_SUCCESS);
}

static int
set_update_dir(char *root, int what)
{
	struct stat	sb;
	int		ret;

	if (is_dir_flag_on(what, NO_MULTI))
		return (BAM_SUCCESS);

	if (!bam_extend) {
		set_dir_flag(what, NO_MULTI);
		return (BAM_SUCCESS);
	}

	if (what == FILE64 && !is_flag_on(IS_SPARC_TARGET))
		ret = snprintf(get_updatedir(what),
		    sizeof (get_updatedir(what)), "%s%s%s/amd64%s", root,
		    ARCHIVE_PREFIX, get_machine(), UPDATEDIR_SUFFIX);
	else
		ret = snprintf(get_updatedir(what),
		    sizeof (get_updatedir(what)), "%s%s%s%s", root,
		    ARCHIVE_PREFIX, get_machine(), UPDATEDIR_SUFFIX);

	if (ret >= sizeof (get_updatedir(what))) {
		bam_error(_("unable to create path on mountpoint %s, "
		    "path too long\n"), rootbuf);
		return (BAM_ERROR);
	}

	if (stat(get_updatedir(what), &sb) == 0) {
		if (S_ISDIR(sb.st_mode))
			ret = rmdir_r(get_updatedir(what));
		else
			ret = unlink(get_updatedir(what));

		if (ret != 0)
			set_dir_flag(what, NO_MULTI);
	}

	if (mkdir(get_updatedir(what), DIR_PERMS) < 0)
		set_dir_flag(what, NO_MULTI);

	return (BAM_SUCCESS);
}

static int
is_valid_archive(char *root, int what)
{
	char 		archive_path[PATH_MAX];
	char		timestamp_path[PATH_MAX];
	struct stat 	sb, timestamp;
	int 		ret;

	if (what == FILE64 && !is_flag_on(IS_SPARC_TARGET))
		ret = snprintf(archive_path, sizeof (archive_path),
		    "%s%s%s/amd64%s", root, ARCHIVE_PREFIX, get_machine(),
		    ARCHIVE_SUFFIX);
	else
		ret = snprintf(archive_path, sizeof (archive_path), "%s%s%s%s",
		    root, ARCHIVE_PREFIX, get_machine(), ARCHIVE_SUFFIX);

	if (ret >= sizeof (archive_path)) {
		bam_error(_("unable to create path on mountpoint %s, "
		    "path too long\n"), rootbuf);
		return (BAM_ERROR);
	}

	if (stat(archive_path, &sb) != 0) {
		if (bam_verbose && !bam_check)
			bam_print(_("archive not found: %s\n"), archive_path);
		set_dir_flag(what, NEED_UPDATE);
		set_dir_flag(what, NO_MULTI);
		return (BAM_SUCCESS);
	}

	/*
	 * The timestamp file is used to prevent stale files in the archive
	 * cache.
	 * Stale files can happen if the system is booted back and forth across
	 * the transition from bootadm-before-the-cache to
	 * bootadm-after-the-cache, since older versions of bootadm don't know
	 * about the existence of the archive cache.
	 *
	 * Since only bootadm-after-the-cache versions know about about this
	 * file, we require that the boot archive be older than this file.
	 */
	ret = snprintf(timestamp_path, sizeof (timestamp_path), "%s%s", root,
	    FILE_STAT_TIMESTAMP);

	if (ret >= sizeof (timestamp_path)) {
		bam_error(_("unable to create path on mountpoint %s, "
		    "path too long\n"), rootbuf);
		return (BAM_ERROR);
	}

	if (stat(timestamp_path, &timestamp) != 0 ||
	    sb.st_mtime > timestamp.st_mtime) {
		if (bam_verbose && !bam_check)
			bam_print(
			    _("archive cache is out of sync. Rebuilding.\n"));
		/*
		 * Don't generate a false positive for the boot-archive service
		 * but trigger an update of the archive cache in
		 * boot-archive-update.
		 */
		if (bam_smf_check) {
			(void) creat(NEED_UPDATE_FILE, 0644);
			return (BAM_SUCCESS);
		}

		set_flag(INVALIDATE_CACHE);
		set_dir_flag(what, NEED_UPDATE);
		set_dir_flag(what, NO_MULTI);
		return (BAM_SUCCESS);
	}

	if (is_flag_on(IS_SPARC_TARGET))
		return (BAM_SUCCESS);

	if (bam_extend && sb.st_size > BA_SIZE_MAX) {
		if (bam_verbose && !bam_check)
			bam_print(_("archive %s is bigger than %d bytes and "
			    "will be rebuilt\n"), archive_path, BA_SIZE_MAX);
		set_dir_flag(what, NO_MULTI);
	}

	return (BAM_SUCCESS);
}

/*
 * Check flags and presence of required files and directories.
 * The force flag and/or absence of files should
 * trigger an update.
 * Suppress stdout output if check (-n) option is set
 * (as -n should only produce parseable output.)
 */
static int
check_flags_and_files(char *root)
{

	struct stat 	sb;
	int 		ret;

	/*
	 * If archive is missing, create archive
	 */
	if (is_flag_on(IS_SPARC_TARGET)) {
		ret = is_valid_archive(root, FILE64);
		if (ret == BAM_ERROR)
			return (BAM_ERROR);
	} else {
		int	what = FILE32;
		do {
			ret = is_valid_archive(root, what);
			if (ret == BAM_ERROR)
				return (BAM_ERROR);
			what++;
		} while (bam_direct == BAM_DIRECT_DBOOT && what < CACHEDIR_NUM);
	}

	if (bam_nowrite())
		return (BAM_SUCCESS);


	/*
	 * check if cache directories exist on x86.
	 * check (and always open) the cache file on SPARC.
	 */
	if (is_sparc()) {
		ret = snprintf(get_cachedir(FILE64),
		    sizeof (get_cachedir(FILE64)), "%s%s%s/%s", root,
		    ARCHIVE_PREFIX, get_machine(), CACHEDIR_SUFFIX);

		if (ret >= sizeof (get_cachedir(FILE64))) {
			bam_error(_("unable to create path on mountpoint %s, "
			    "path too long\n"), rootbuf);
			return (BAM_ERROR);
		}

		if (stat(get_cachedir(FILE64), &sb) != 0) {
			set_flag(NEED_CACHE_DIR);
			set_dir_flag(FILE64, NEED_UPDATE);
		}

		walk_arg.sparcfile = fopen(get_cachedir(FILE64), "w");
		if (walk_arg.sparcfile == NULL) {
			bam_error(_("failed to open file: %s: %s\n"),
			    get_cachedir(FILE64), strerror(errno));
			return (BAM_ERROR);
		}

		set_dir_present(FILE64);
	} else {
		int	what = FILE32;

		do {
			if (set_cache_dir(root, what) != 0)
				return (BAM_ERROR);

			set_dir_present(what);

			if (set_update_dir(root, what) != 0)
				return (BAM_ERROR);
			what++;
		} while (bam_direct == BAM_DIRECT_DBOOT && what < CACHEDIR_NUM);
	}

	/*
	 * if force, create archive unconditionally
	 */
	if (bam_force) {
		if (!is_sparc())
			set_dir_flag(FILE32, NEED_UPDATE);
		set_dir_flag(FILE64, NEED_UPDATE);
		if (bam_verbose)
			bam_print(_("forced update of archive requested\n"));
		return (BAM_SUCCESS);
	}

	return (BAM_SUCCESS);
}

static error_t
read_one_list(char *root, filelist_t  *flistp, char *filelist)
{
	char 		path[PATH_MAX];
	FILE 		*fp;
	char 		buf[BAM_MAXLINE];
	const char 	*fcn = "read_one_list()";

	(void) snprintf(path, sizeof (path), "%s%s", root, filelist);

	fp = fopen(path, "r");
	if (fp == NULL) {
		BAM_DPRINTF(("%s: failed to open archive filelist: %s: %s\n",
		    fcn, path, strerror(errno)));
		return (BAM_ERROR);
	}
	while (s_fgets(buf, sizeof (buf), fp) != NULL) {
		/* skip blank lines */
		if (strspn(buf, " \t") == strlen(buf))
			continue;
		append_to_flist(flistp, buf);
	}
	if (fclose(fp) != 0) {
		bam_error(_("failed to close file: %s: %s\n"),
		    path, strerror(errno));
		return (BAM_ERROR);
	}
	return (BAM_SUCCESS);
}

static error_t
read_list(char *root, filelist_t  *flistp)
{
	char 		path[PATH_MAX];
	char 		cmd[PATH_MAX];
	struct stat 	sb;
	int 		n, rval;
	const char 	*fcn = "read_list()";

	flistp->head = flistp->tail = NULL;

	/*
	 * build and check path to extract_boot_filelist.ksh
	 */
	n = snprintf(path, sizeof (path), "%s%s", root, EXTRACT_BOOT_FILELIST);
	if (n >= sizeof (path)) {
		bam_error(_("archive filelist is empty\n"));
		return (BAM_ERROR);
	}

	if (is_safe_exec(path) == BAM_ERROR)
		return (BAM_ERROR);

	/*
	 * If extract_boot_filelist is present, exec it, otherwise read
	 * the filelists directly, for compatibility with older images.
	 */
	if (stat(path, &sb) == 0) {
		/*
		 * build arguments to exec extract_boot_filelist.ksh
		 */
		char *rootarg, *platarg;
		int platarglen = 1, rootarglen = 1;
		if (strlen(root) > 1)
			rootarglen += strlen(root) + strlen("-R ");
		if (bam_alt_platform)
			platarglen += strlen(bam_platform) + strlen("-p ");
		platarg = s_calloc(1, platarglen);
		rootarg = s_calloc(1, rootarglen);
		*platarg = 0;
		*rootarg = 0;

		if (strlen(root) > 1) {
			(void) snprintf(rootarg, rootarglen,
			    "-R %s", root);
		}
		if (bam_alt_platform) {
			(void) snprintf(platarg, platarglen,
			    "-p %s", bam_platform);
		}
		n = snprintf(cmd, sizeof (cmd), "%s %s %s /%s /%s",
		    path, rootarg, platarg, BOOT_FILE_LIST, ETC_FILE_LIST);
		free(platarg);
		free(rootarg);
		if (n >= sizeof (cmd)) {
			bam_error(_("archive filelist is empty\n"));
			return (BAM_ERROR);
		}
		if (exec_cmd(cmd, flistp) != 0) {
			BAM_DPRINTF(("%s: failed to open archive "
			    "filelist: %s: %s\n", fcn, path, strerror(errno)));
			return (BAM_ERROR);
		}
	} else {
		/*
		 * Read current lists of files - only the first is mandatory
		 */
		rval = read_one_list(root, flistp, BOOT_FILE_LIST);
		if (rval != BAM_SUCCESS)
			return (rval);
		(void) read_one_list(root, flistp, ETC_FILE_LIST);
	}

	if (flistp->head == NULL) {
		bam_error(_("archive filelist is empty\n"));
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

static void
getoldstat(char *root)
{
	char 		path[PATH_MAX];
	int 		fd, error;
	struct stat 	sb;
	char 		*ostat;

	(void) snprintf(path, sizeof (path), "%s%s", root, FILE_STAT);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (bam_verbose)
			bam_print(_("failed to open file: %s: %s\n"),
			    path, strerror(errno));
		goto out_err;
	}

	if (fstat(fd, &sb) != 0) {
		bam_error(_("stat of file failed: %s: %s\n"), path,
		    strerror(errno));
		goto out_err;
	}

	ostat = s_calloc(1, sb.st_size);

	if (read(fd, ostat, sb.st_size) != sb.st_size) {
		bam_error(_("read failed for file: %s: %s\n"), path,
		    strerror(errno));
		free(ostat);
		goto out_err;
	}

	(void) close(fd);
	fd = -1;

	walk_arg.old_nvlp = NULL;
	error = nvlist_unpack(ostat, sb.st_size, &walk_arg.old_nvlp, 0);

	free(ostat);

	if (error) {
		bam_error(_("failed to unpack stat data: %s: %s\n"),
		    path, strerror(error));
		walk_arg.old_nvlp = NULL;
		goto out_err;
	} else {
		return;
	}

out_err:
	if (fd != -1)
		(void) close(fd);
	if (!is_flag_on(IS_SPARC_TARGET))
		set_dir_flag(FILE32, NEED_UPDATE);
	set_dir_flag(FILE64, NEED_UPDATE);
}

/* Best effort stale entry removal */
static void
delete_stale(char *file, int what)
{
	char		path[PATH_MAX];
	struct stat	sb;

	(void) snprintf(path, sizeof (path), "%s/%s", get_cachedir(what), file);
	if (!bam_check && stat(path, &sb) == 0) {
		if (sb.st_mode & S_IFDIR)
			(void) rmdir_r(path);
		else
			(void) unlink(path);

		set_dir_flag(what, (NEED_UPDATE | NO_MULTI));
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

	/*
	 * Skip stale file check during smf check
	 */
	if (bam_smf_check)
		return;

	/*
	 * If we need to (re)create the cache, there's no need to check for
	 * stale files
	 */
	if (is_flag_on(NEED_CACHE_DIR))
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
		if (access(path, F_OK) < 0) {
			int	what;

			if (bam_verbose)
				bam_print(_("    stale %s\n"), path);

			if (is_flag_on(IS_SPARC_TARGET)) {
				set_dir_flag(FILE64, NEED_UPDATE);
			} else {
				for (what = FILE32; what < CACHEDIR_NUM; what++)
					if (has_cachedir(what))
						delete_stale(file, what);
			}
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
		bam_error(_("failed to create stat data: %s\n"),
		    strerror(error));
	}
}

static int
walk_list(char *root, filelist_t *flistp)
{
	char path[PATH_MAX];
	line_t *lp;

	for (lp = flistp->head; lp; lp = lp->next) {
		/*
		 * Don't follow symlinks.  A symlink must refer to
		 * a file that would appear in the archive through
		 * a direct reference.  This matches the archive
		 * construction behavior.
		 */
		(void) snprintf(path, sizeof (path), "%s%s", root, lp->line);
		if (nftw(path, cmpstat, 20, FTW_PHYS) == -1) {
			if (is_flag_on(UPDATE_ERROR))
				return (BAM_ERROR);
			/*
			 * Some files may not exist.
			 * For example: etc/rtc_config on a x86 diskless system
			 * Emit verbose message only
			 */
			if (bam_verbose)
				bam_print(_("cannot find: %s: %s\n"),
				    path, strerror(errno));
		}
	}

	return (BAM_SUCCESS);
}

/*
 * Update the timestamp file.
 */
static void
update_timestamp(char *root)
{
	char	timestamp_path[PATH_MAX];

	/* this path length has already been checked in check_flags_and_files */
	(void) snprintf(timestamp_path, sizeof (timestamp_path), "%s%s", root,
	    FILE_STAT_TIMESTAMP);

	/*
	 * recreate the timestamp file. Since an outdated or absent timestamp
	 * file translates in a complete rebuild of the archive cache, notify
	 * the user of the performance issue.
	 */
	if (creat(timestamp_path, FILE_STAT_MODE) < 0) {
		bam_error(_("failed to open file: %s: %s\n"), timestamp_path,
		    strerror(errno));
		bam_error(_("failed to update the timestamp file, next"
		    " archive update may experience reduced performance\n"));
	}
}


static void
savenew(char *root)
{
	char 	path[PATH_MAX];
	char 	path2[PATH_MAX];
	size_t 	sz;
	char 	*nstat;
	int 	fd, wrote, error;

	nstat = NULL;
	sz = 0;
	error = nvlist_pack(walk_arg.new_nvlp, &nstat, &sz,
	    NV_ENCODE_XDR, 0);
	if (error) {
		bam_error(_("failed to pack stat data: %s\n"),
		    strerror(error));
		return;
	}

	(void) snprintf(path, sizeof (path), "%s%s", root, FILE_STAT_TMP);
	fd = open(path, O_RDWR|O_CREAT|O_TRUNC, FILE_STAT_MODE);
	if (fd == -1) {
		bam_error(_("failed to open file: %s: %s\n"), path,
		    strerror(errno));
		free(nstat);
		return;
	}
	wrote = write(fd, nstat, sz);
	if (wrote != sz) {
		bam_error(_("write to file failed: %s: %s\n"), path,
		    strerror(errno));
		(void) close(fd);
		free(nstat);
		return;
	}
	(void) close(fd);
	free(nstat);

	(void) snprintf(path2, sizeof (path2), "%s%s", root, FILE_STAT);
	if (rename(path, path2) != 0) {
		bam_error(_("rename to file failed: %s: %s\n"), path2,
		    strerror(errno));
	}
}

#define	init_walk_args()	bzero(&walk_arg, sizeof (walk_arg))

static void
clear_walk_args(void)
{
	nvlist_free(walk_arg.old_nvlp);
	nvlist_free(walk_arg.new_nvlp);
	if (walk_arg.sparcfile)
		(void) fclose(walk_arg.sparcfile);
	walk_arg.old_nvlp = NULL;
	walk_arg.new_nvlp = NULL;
	walk_arg.sparcfile = NULL;
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
	struct stat 	sb;
	char 		path[PATH_MAX];
	filelist_t 	flist;
	filelist_t 	*flistp = &flist;
	int 		ret;

	flistp->head = flistp->tail = NULL;

	if (is_sparc())
		set_flag(IS_SPARC_TARGET);

	/*
	 * Check if cache directories and archives are present
	 */

	ret = check_flags_and_files(root);
	if (ret < 0)
		return (BAM_ERROR);

	/*
	 * In certain deployment scenarios, filestat may not
	 * exist. Do not stop the boot process, but trigger an update
	 * of the archives (which will recreate filestat.ramdisk).
	 */
	if (bam_smf_check) {
		(void) snprintf(path, sizeof (path), "%s%s", root, FILE_STAT);
		if (stat(path, &sb) != 0) {
			(void) creat(NEED_UPDATE_FILE, 0644);
			return (0);
		}
	}

	getoldstat(root);

	/*
	 * Check if the archive contains files that are no longer
	 * present on the root filesystem.
	 */
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
	ret = walk_list(root, &flist);

	/* done with the file list */
	filelist_free(flistp);

	/* something went wrong */

	if (ret == BAM_ERROR) {
		bam_error(_("Failed to gather cache files, archives "
		    "generation aborted\n"));
		return (BAM_ERROR);
	}

	if (walk_arg.new_nvlp == NULL) {
		if (walk_arg.sparcfile != NULL)
			(void) fclose(walk_arg.sparcfile);
		bam_error(_("cannot create new stat data\n"));
	}

	/* If nothing was updated, discard newstat. */

	if (!is_dir_flag_on(FILE32, NEED_UPDATE) &&
	    !is_dir_flag_on(FILE64, NEED_UPDATE)) {
		clear_walk_args();
		return (0);
	}

	if (walk_arg.sparcfile != NULL)
		(void) fclose(walk_arg.sparcfile);

	return (1);
}

static int
flushfs(char *root)
{
	char	cmd[PATH_MAX + 30];

	(void) snprintf(cmd, sizeof (cmd), "%s -f \"%s\" 2>/dev/null",
	    LOCKFS_PATH, root);

	return (exec_cmd(cmd, NULL));
}

static int
do_archive_copy(char *source, char *dest)
{

	sync();

	/* the equivalent of mv archive-new-$pid boot_archive */
	if (rename(source, dest) != 0) {
		(void) unlink(source);
		return (BAM_ERROR);
	}

	if (flushfs(bam_root) != 0)
		sync();

	return (BAM_SUCCESS);
}

static int
check_cmdline(filelist_t flist)
{
	line_t	*lp;

	for (lp = flist.head; lp; lp = lp->next) {
		if (strstr(lp->line, "Error:") != NULL ||
		    strstr(lp->line, "Inode number overflow") != NULL) {
			(void) fprintf(stderr, "%s\n", lp->line);
			return (BAM_ERROR);
		}
	}

	return (BAM_SUCCESS);
}

static void
dump_errormsg(filelist_t flist)
{
	line_t	*lp;

	for (lp = flist.head; lp; lp = lp->next)
		(void) fprintf(stderr, "%s\n", lp->line);
}

static int
check_archive(char *dest)
{
	struct stat	sb;

	if (stat(dest, &sb) != 0 || !S_ISREG(sb.st_mode) ||
	    sb.st_size < 10000) {
		bam_error(_("archive file %s not generated correctly\n"), dest);
		(void) unlink(dest);
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

static boolean_t
is_be(char *root)
{
	zfs_handle_t	*zhp;
	libzfs_handle_t	*hdl;
	be_node_list_t	*be_nodes = NULL;
	be_node_list_t	*cur_be;
	boolean_t	be_exist = B_FALSE;
	char		ds_path[ZFS_MAX_DATASET_NAME_LEN];

	if (!is_zfs(root))
		return (B_FALSE);
	/*
	 * Get dataset for mountpoint
	 */
	if ((hdl = libzfs_init()) == NULL)
		return (B_FALSE);

	if ((zhp = zfs_path_to_zhandle(hdl, root,
	    ZFS_TYPE_FILESYSTEM)) == NULL) {
		libzfs_fini(hdl);
		return (B_FALSE);
	}

	(void) strlcpy(ds_path, zfs_get_name(zhp), sizeof (ds_path));

	/*
	 * Check if the current dataset is BE
	 */
	if (be_list(NULL, &be_nodes) == BE_SUCCESS) {
		for (cur_be = be_nodes; cur_be != NULL;
		    cur_be = cur_be->be_next_node) {

			/*
			 * Because we guarantee that cur_be->be_root_ds
			 * is null-terminated by internal data structure,
			 * we can safely use strcmp()
			 */
			if (strcmp(ds_path, cur_be->be_root_ds) == 0) {
				be_exist = B_TRUE;
				break;
			}
		}
		be_free_list(be_nodes);
	}
	zfs_close(zhp);
	libzfs_fini(hdl);

	return (be_exist);
}

/*
 * Returns 1 if mkiso is in the expected PATH, 0 otherwise
 */
static int
is_mkisofs()
{
	if (access(MKISOFS_PATH, X_OK) == 0)
		return (1);
	return (0);
}

#define	MKISO_PARAMS	" -quiet -graft-points -dlrDJN -relaxed-filenames "

static int
create_sparc_archive(char *archive, char *tempname, char *bootblk, char *list)
{
	int		ret;
	char		cmdline[3 * PATH_MAX + 64];
	filelist_t	flist = {0};
	const char	*func = "create_sparc_archive()";

	if (access(bootblk, R_OK) == 1) {
		bam_error(_("unable to access bootblk file : %s\n"), bootblk);
		return (BAM_ERROR);
	}

	/*
	 * Prepare mkisofs command line and execute it
	 */
	(void) snprintf(cmdline, sizeof (cmdline), "%s %s -G %s -o \"%s\" "
	    "-path-list \"%s\" 2>&1", MKISOFS_PATH, MKISO_PARAMS, bootblk,
	    tempname, list);

	BAM_DPRINTF(("%s: executing: %s\n", func, cmdline));

	ret = exec_cmd(cmdline, &flist);
	if (ret != 0 || check_cmdline(flist) == BAM_ERROR) {
		dump_errormsg(flist);
		goto out_err;
	}

	filelist_free(&flist);

	/*
	 * Prepare dd command line to copy the bootblk on the new archive and
	 * execute it
	 */
	(void) snprintf(cmdline, sizeof (cmdline), "%s if=\"%s\" of=\"%s\""
	    " bs=1b oseek=1 count=15 conv=notrunc conv=sync 2>&1", DD_PATH_USR,
	    bootblk, tempname);

	BAM_DPRINTF(("%s: executing: %s\n", func, cmdline));

	ret = exec_cmd(cmdline, &flist);
	if (ret != 0 || check_cmdline(flist) == BAM_ERROR)
		goto out_err;

	filelist_free(&flist);

	/* Did we get a valid archive ? */
	if (check_archive(tempname) == BAM_ERROR)
		return (BAM_ERROR);

	return (do_archive_copy(tempname, archive));

out_err:
	filelist_free(&flist);
	bam_error(_("boot-archive creation FAILED, command: '%s'\n"), cmdline);
	(void) unlink(tempname);
	return (BAM_ERROR);
}

static unsigned int
from_733(unsigned char *s)
{
	int		i;
	unsigned int	ret = 0;

	for (i = 0; i < 4; i++)
		ret |= s[i] << (8 * i);

	return (ret);
}

static void
to_733(unsigned char *s, unsigned int val)
{
	int	i;

	for (i = 0; i < 4; i++)
		s[i] = s[7-i] = (val >> (8 * i)) & 0xFF;
}

/*
 * creates sha1 hash of archive
 */
static int
digest_archive(const char *archive)
{
	char *archive_hash;
	char *hash;
	int ret;
	FILE *fp;

	(void) asprintf(&archive_hash, "%s.hash", archive);
	if (archive_hash == NULL)
		return (BAM_ERROR);

	if ((ret = bootadm_digest(archive, &hash)) == BAM_ERROR) {
		free(archive_hash);
		return (ret);
	}

	fp = fopen(archive_hash, "w");
	if (fp == NULL) {
		free(archive_hash);
		free(hash);
		return (BAM_ERROR);
	}

	(void) fprintf(fp, "%s\n", hash);
	(void) fclose(fp);
	free(hash);
	free(archive_hash);
	return (BAM_SUCCESS);
}

/*
 * Extends the current boot archive without recreating it from scratch
 */
static int
extend_iso_archive(char *archive, char *tempname, char *update_dir)
{
	int			fd = -1, newfd = -1, ret, i;
	int			next_session = 0, new_size = 0;
	char			cmdline[3 * PATH_MAX + 64];
	const char		*func = "extend_iso_archive()";
	filelist_t		flist = {0};
	struct iso_pdesc	saved_desc[MAX_IVDs];

	fd = open(archive, O_RDWR);
	if (fd == -1) {
		if (bam_verbose)
			bam_error(_("failed to open file: %s: %s\n"),
			    archive, strerror(errno));
		goto out_err;
	}

	/*
	 * A partial read is likely due to a corrupted file
	 */
	ret = pread64(fd, saved_desc, sizeof (saved_desc),
	    VOLDESC_OFF * CD_BLOCK);
	if (ret != sizeof (saved_desc)) {
		if (bam_verbose)
			bam_error(_("read failed for file: %s: %s\n"),
			    archive, strerror(errno));
		goto out_err;
	}

	if (memcmp(saved_desc[0].type, "\1CD001", 6)) {
		if (bam_verbose)
			bam_error(_("iso descriptor signature for %s is "
			    "invalid\n"), archive);
		goto out_err;
	}

	/*
	 * Read primary descriptor and locate next_session offset (it should
	 * point to the end of the archive)
	 */
	next_session = P2ROUNDUP(from_733(saved_desc[0].volume_space_size), 16);

	(void) snprintf(cmdline, sizeof (cmdline), "%s -C 16,%d -M %s %s -o \""
	    "%s\" \"%s\" 2>&1", MKISOFS_PATH, next_session, archive,
	    MKISO_PARAMS, tempname, update_dir);

	BAM_DPRINTF(("%s: executing: %s\n", func, cmdline));

	ret = exec_cmd(cmdline, &flist);
	if (ret != 0 || check_cmdline(flist) == BAM_ERROR) {
		if (bam_verbose) {
			bam_error(_("Command '%s' failed while generating "
			    "multisession archive\n"), cmdline);
			dump_errormsg(flist);
		}
		goto out_flist_err;
	}
	filelist_free(&flist);

	newfd = open(tempname, O_RDONLY);
	if (newfd == -1) {
		if (bam_verbose)
			bam_error(_("failed to open file: %s: %s\n"),
			    archive, strerror(errno));
		goto out_err;
	}

	ret = pread64(newfd, saved_desc, sizeof (saved_desc),
	    VOLDESC_OFF * CD_BLOCK);
	if (ret != sizeof (saved_desc)) {
		if (bam_verbose)
			bam_error(_("read failed for file: %s: %s\n"),
			    archive, strerror(errno));
		goto out_err;
	}

	if (memcmp(saved_desc[0].type, "\1CD001", 6)) {
		if (bam_verbose)
			bam_error(_("iso descriptor signature for %s is "
			    "invalid\n"), archive);
		goto out_err;
	}

	new_size = from_733(saved_desc[0].volume_space_size) + next_session;
	to_733(saved_desc[0].volume_space_size, new_size);

	for (i = 1; i < MAX_IVDs; i++) {
		if (saved_desc[i].type[0] == (unsigned char)255)
			break;
		if (memcmp(saved_desc[i].id, "CD001", 5))
			break;

		if (bam_verbose)
			bam_print("%s: Updating descriptor entry [%d]\n", func,
			    i);

		to_733(saved_desc[i].volume_space_size, new_size);
	}

	ret = pwrite64(fd, saved_desc, DVD_BLOCK, VOLDESC_OFF*CD_BLOCK);
	if (ret != DVD_BLOCK) {
		if (bam_verbose)
			bam_error(_("write to file failed: %s: %s\n"),
			    archive, strerror(errno));
		goto out_err;
	}
	(void) close(newfd);
	newfd = -1;

	ret = fsync(fd);
	if (ret != 0)
		sync();

	ret = close(fd);
	if (ret != 0) {
		if (bam_verbose)
			bam_error(_("failed to close file: %s: %s\n"),
			    archive, strerror(errno));
		return (BAM_ERROR);
	}
	fd = -1;

	(void) snprintf(cmdline, sizeof (cmdline), "%s if=%s of=%s bs=32k "
	    "seek=%d conv=sync 2>&1", DD_PATH_USR, tempname, archive,
	    (next_session/16));

	BAM_DPRINTF(("%s: executing: %s\n", func, cmdline));

	ret = exec_cmd(cmdline, &flist);
	if (ret != 0 || check_cmdline(flist) == BAM_ERROR) {
		if (bam_verbose)
			bam_error(_("Command '%s' failed while generating "
			    "multisession archive\n"), cmdline);
		goto out_flist_err;
	}
	filelist_free(&flist);

	(void) unlink(tempname);

	if (digest_archive(archive) == BAM_ERROR && bam_verbose)
		bam_print("boot archive hashing failed\n");

	if (flushfs(bam_root) != 0)
		sync();

	if (bam_verbose)
		bam_print("boot archive updated successfully\n");

	return (BAM_SUCCESS);

out_flist_err:
	filelist_free(&flist);
out_err:
	if (fd != -1)
		(void) close(fd);
	if (newfd != -1)
		(void) close(newfd);
	return (BAM_ERROR);
}

static int
create_x86_archive(char *archive, char *tempname, char *update_dir)
{
	int		ret;
	char		cmdline[3 * PATH_MAX + 64];
	filelist_t	flist = {0};
	const char	*func = "create_x86_archive()";

	(void) snprintf(cmdline, sizeof (cmdline), "%s %s -o \"%s\" \"%s\" "
	    "2>&1", MKISOFS_PATH, MKISO_PARAMS, tempname, update_dir);

	BAM_DPRINTF(("%s: executing: %s\n", func, cmdline));

	ret = exec_cmd(cmdline, &flist);
	if (ret != 0 || check_cmdline(flist) == BAM_ERROR) {
		bam_error(_("boot-archive creation FAILED, command: '%s'\n"),
		    cmdline);
		dump_errormsg(flist);
		filelist_free(&flist);
		(void) unlink(tempname);
		return (BAM_ERROR);
	}

	filelist_free(&flist);

	if (check_archive(tempname) == BAM_ERROR)
		return (BAM_ERROR);

	return (do_archive_copy(tempname, archive));
}

static int
mkisofs_archive(char *root, int what)
{
	int		ret;
	char		temp[PATH_MAX];
	char 		bootblk[PATH_MAX];
	char		boot_archive[PATH_MAX];

	if (what == FILE64 && !is_flag_on(IS_SPARC_TARGET))
		ret = snprintf(temp, sizeof (temp),
		    "%s%s%s/amd64/archive-new-%d", root, ARCHIVE_PREFIX,
		    get_machine(), getpid());
	else
		ret = snprintf(temp, sizeof (temp), "%s%s%s/archive-new-%d",
		    root, ARCHIVE_PREFIX, get_machine(), getpid());

	if (ret >= sizeof (temp))
		goto out_path_err;

	if (what == FILE64 && !is_flag_on(IS_SPARC_TARGET))
		ret = snprintf(boot_archive, sizeof (boot_archive),
		    "%s%s%s/amd64%s", root, ARCHIVE_PREFIX, get_machine(),
		    ARCHIVE_SUFFIX);
	else
		ret = snprintf(boot_archive, sizeof (boot_archive),
		    "%s%s%s%s", root, ARCHIVE_PREFIX, get_machine(),
		    ARCHIVE_SUFFIX);

	if (ret >= sizeof (boot_archive))
		goto out_path_err;

	bam_print("updating %s\n", boot_archive);

	if (is_flag_on(IS_SPARC_TARGET)) {
		ret = snprintf(bootblk, sizeof (bootblk),
		    "%s/platform/%s/lib/fs/hsfs/bootblk", root, get_machine());
		if (ret >= sizeof (bootblk))
			goto out_path_err;

		ret = create_sparc_archive(boot_archive, temp, bootblk,
		    get_cachedir(what));
	} else {
		if (!is_dir_flag_on(what, NO_MULTI)) {
			if (bam_verbose)
				bam_print("Attempting to extend x86 archive: "
				    "%s\n", boot_archive);

			ret = extend_iso_archive(boot_archive, temp,
			    get_updatedir(what));
			if (ret == BAM_SUCCESS) {
				if (bam_verbose)
					bam_print("Successfully extended %s\n",
					    boot_archive);

				(void) rmdir_r(get_updatedir(what));
				return (BAM_SUCCESS);
			}
		}
		/*
		 * The boot archive will be recreated from scratch. We get here
		 * if at least one of these conditions is true:
		 * - bootadm was called without the -e switch
		 * - the archive (or the archive cache) doesn't exist
		 * - archive size is bigger than BA_SIZE_MAX
		 * - more than COUNT_MAX files need to be updated
		 * - an error occourred either populating the /updates directory
		 *   or extend_iso_archive() failed
		 */
		if (bam_verbose)
			bam_print("Unable to extend %s... rebuilding archive\n",
			    boot_archive);

		if (get_updatedir(what)[0] != '\0')
			(void) rmdir_r(get_updatedir(what));


		ret = create_x86_archive(boot_archive, temp,
		    get_cachedir(what));
	}

	if (digest_archive(boot_archive) == BAM_ERROR && bam_verbose)
		bam_print("boot archive hashing failed\n");

	if (ret == BAM_SUCCESS && bam_verbose)
		bam_print("Successfully created %s\n", boot_archive);

	return (ret);

out_path_err:
	bam_error(_("unable to create path on mountpoint %s, path too long\n"),
	    root);
	return (BAM_ERROR);
}

static error_t
create_ramdisk(char *root)
{
	char *cmdline, path[PATH_MAX];
	size_t len;
	struct stat sb;
	int ret, what, status = BAM_SUCCESS;

	/* If there is mkisofs, use it to create the required archives */
	if (is_mkisofs()) {
		for (what = FILE32; what < CACHEDIR_NUM; what++) {
			if (has_cachedir(what) && is_dir_flag_on(what,
			    NEED_UPDATE)) {
				ret = mkisofs_archive(root, what);
				if (ret != 0)
					status = BAM_ERROR;
			}
		}
		return (status);
	}

	/*
	 * Else setup command args for create_ramdisk.ksh for the UFS archives
	 * Note: we will not create hash here, CREATE_RAMDISK should create it.
	 */
	if (bam_verbose)
		bam_print("mkisofs not found, creating UFS archive\n");

	(void) snprintf(path, sizeof (path), "%s/%s", root, CREATE_RAMDISK);
	if (stat(path, &sb) != 0) {
		bam_error(_("archive creation file not found: %s: %s\n"),
		    path, strerror(errno));
		return (BAM_ERROR);
	}

	if (is_safe_exec(path) == BAM_ERROR)
		return (BAM_ERROR);

	len = strlen(path) + strlen(root) + 10;	/* room for space + -R */
	if (bam_alt_platform)
		len += strlen(bam_platform) + strlen("-p ");
	cmdline = s_calloc(1, len);

	if (bam_alt_platform) {
		assert(strlen(root) > 1);
		(void) snprintf(cmdline, len, "%s -p %s -R %s",
		    path, bam_platform, root);
		/* chop off / at the end */
		cmdline[strlen(cmdline) - 1] = '\0';
	} else if (strlen(root) > 1) {
		(void) snprintf(cmdline, len, "%s -R %s", path, root);
		/* chop off / at the end */
		cmdline[strlen(cmdline) - 1] = '\0';
	} else
		(void) snprintf(cmdline, len, "%s", path);

	if (exec_cmd(cmdline, NULL) != 0) {
		bam_error(_("boot-archive creation FAILED, command: '%s'\n"),
		    cmdline);
		free(cmdline);
		return (BAM_ERROR);
	}
	free(cmdline);
	/*
	 * The existence of the expected archives used to be
	 * verified here. This check is done in create_ramdisk as
	 * it needs to be in sync with the altroot operated upon.
	 */
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
		bam_error(_("failed to open file: %s: %s\n"),
		    MNTTAB, strerror(errno));
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
			bam_error(_("alternate root %s not in mnttab\n"),
			    mntpt);
		(void) fclose(fp);
		return (0);
	}

	if (strncmp(mnt.mnt_special, RAMDISK_SPECIAL,
	    strlen(RAMDISK_SPECIAL)) == 0) {
		if (bam_verbose)
			bam_error(_("%s is on a ramdisk device\n"), bam_root);
		(void) fclose(fp);
		return (1);
	}

	(void) fclose(fp);

	return (0);
}

static int
is_boot_archive(char *root)
{
	char		path[PATH_MAX];
	struct stat	sb;
	int		error;
	const char	*fcn = "is_boot_archive()";

	/*
	 * We can't create an archive without the create_ramdisk script
	 */
	(void) snprintf(path, sizeof (path), "%s/%s", root, CREATE_RAMDISK);
	error = stat(path, &sb);
	INJECT_ERROR1("NOT_ARCHIVE_BASED", error = -1);
	if (error == -1) {
		if (bam_verbose)
			bam_print(_("file not found: %s\n"), path);
		BAM_DPRINTF(("%s: not a boot archive based Solaris "
		    "instance: %s\n", fcn, root));
		return (0);
	}

	BAM_DPRINTF(("%s: *IS* a boot archive based Solaris instance: %s\n",
	    fcn, root));
	return (1);
}

/*
 * Need to call this for anything that operates on the GRUB menu
 * In the x86 live upgrade case the directory /boot/grub may be present
 * even on pre-newboot BEs. The authoritative way to check for a GRUB target
 * is to check for the presence of the stage2 binary which is present
 * only on GRUB targets (even on x86 boot partitions). Checking for the
 * presence of the multiboot binary is not correct as it is not present
 * on x86 boot partitions.
 */
int
is_grub(const char *root)
{
	char path[PATH_MAX];
	struct stat sb;
	void *defp;
	boolean_t grub = B_FALSE;
	const char *res = NULL;
	const char *fcn = "is_grub()";

	/* grub is disabled by default */
	if ((defp = defopen_r(BE_DEFAULTS)) == NULL) {
		return (0);
	} else {
		res = defread_r(BE_DFLT_BE_HAS_GRUB, defp);
		if (res != NULL && res[0] != '\0') {
			if (strcasecmp(res, "true") == 0)
				grub = B_TRUE;
		}
		defclose_r(defp);
	}

	if (grub == B_TRUE) {
		(void) snprintf(path, sizeof (path), "%s%s", root, GRUB_STAGE2);
		if (stat(path, &sb) == -1) {
			BAM_DPRINTF(("%s: Missing GRUB directory: %s\n",
			    fcn, path));
			return (0);
		} else
			return (1);
	}

	return (0);
}

int
is_zfs(char *root)
{
	struct statvfs		vfs;
	int			ret;
	const char		*fcn = "is_zfs()";

	ret = statvfs(root, &vfs);
	INJECT_ERROR1("STATVFS_ZFS", ret = 1);
	if (ret != 0) {
		bam_error(_("statvfs failed for %s: %s\n"), root,
		    strerror(errno));
		return (0);
	}

	if (strncmp(vfs.f_basetype, "zfs", strlen("zfs")) == 0) {
		BAM_DPRINTF(("%s: is a ZFS filesystem: %s\n", fcn, root));
		return (1);
	} else {
		BAM_DPRINTF(("%s: is *NOT* a ZFS filesystem: %s\n", fcn, root));
		return (0);
	}
}

int
is_pcfs(char *root)
{
	struct statvfs		vfs;
	int			ret;
	const char		*fcn = "is_pcfs()";

	ret = statvfs(root, &vfs);
	INJECT_ERROR1("STATVFS_PCFS", ret = 1);
	if (ret != 0) {
		bam_error(_("statvfs failed for %s: %s\n"), root,
		    strerror(errno));
		return (0);
	}

	if (strncmp(vfs.f_basetype, "pcfs", strlen("pcfs")) == 0) {
		BAM_DPRINTF(("%s: is a PCFS filesystem: %s\n", fcn, root));
		return (1);
	} else {
		BAM_DPRINTF(("%s: is *NOT* a PCFS filesystem: %s\n",
		    fcn, root));
		return (0);
	}
}

static int
is_readonly(char *root)
{
	int		fd;
	int		error;
	char		testfile[PATH_MAX];
	const char	*fcn = "is_readonly()";

	/*
	 * Using statvfs() to check for a read-only filesystem is not
	 * reliable. The only way to reliably test is to attempt to
	 * create a file
	 */
	(void) snprintf(testfile, sizeof (testfile), "%s/%s.%d",
	    root, BOOTADM_RDONLY_TEST, getpid());

	(void) unlink(testfile);

	errno = 0;
	fd = open(testfile, O_RDWR|O_CREAT|O_EXCL, 0644);
	error = errno;
	INJECT_ERROR2("RDONLY_TEST_ERROR", fd = -1, error = EACCES);
	if (fd == -1 && error == EROFS) {
		BAM_DPRINTF(("%s: is a READONLY filesystem: %s\n", fcn, root));
		return (1);
	} else if (fd == -1) {
		bam_error(_("error during read-only test on %s: %s\n"),
		    root, strerror(error));
	}

	(void) close(fd);
	(void) unlink(testfile);

	BAM_DPRINTF(("%s: is a RDWR filesystem: %s\n", fcn, root));
	return (0);
}

static error_t
update_archive(char *root, char *opt)
{
	error_t ret;

	assert(root);
	assert(opt == NULL);

	init_walk_args();
	(void) umask(022);

	/*
	 * Never update non-BE root in update_all
	 */
	if (!is_be(root) && bam_update_all)
		return (BAM_SUCCESS);
	/*
	 * root must belong to a boot archive based OS,
	 */
	if (!is_boot_archive(root)) {
		/*
		 * Emit message only if not in context of update_all.
		 * If in update_all, emit only if verbose flag is set.
		 */
		if (!bam_update_all || bam_verbose)
			bam_print(_("%s: not a boot archive based Solaris "
			    "instance\n"), root);
		return (BAM_ERROR);
	}

	/*
	 * If smf check is requested when / is writable (can happen
	 * on first reboot following an upgrade because service
	 * dependency is messed up), skip the check.
	 */
	if (bam_smf_check && !bam_root_readonly && !is_zfs(root))
		return (BAM_SUCCESS);

	/*
	 * Don't generate archive on ramdisk.
	 */
	if (is_ramdisk(root))
		return (BAM_SUCCESS);

	/*
	 * root must be writable. This check applies to alternate
	 * root (-R option); bam_root_readonly applies to '/' only.
	 * The behaviour translates into being the one of a 'check'.
	 */
	if (!bam_smf_check && !bam_check && is_readonly(root)) {
		set_flag(RDONLY_FSCHK);
		bam_check = 1;
	}

	/*
	 * Now check if an update is really needed.
	 */
	ret = update_required(root);

	/*
	 * The check command (-n) is *not* a dry run.
	 * It only checks if the archive is in sync.
	 * A readonly filesystem has to be considered an error only if an update
	 * is required.
	 */
	if (bam_nowrite()) {
		if (is_flag_on(RDONLY_FSCHK)) {
			bam_check = bam_saved_check;
			if (ret > 0)
				bam_error(_("%s filesystem is read-only, "
				    "skipping archives update\n"), root);
			if (bam_update_all)
				return ((ret != 0) ? BAM_ERROR : BAM_SUCCESS);
		}

		bam_exit((ret != 0) ? 1 : 0);
	}

	if (ret == 1) {
		/* create the ramdisk */
		ret = create_ramdisk(root);
	}

	/*
	 * if the archive is updated, save the new stat data and update the
	 * timestamp file
	 */
	if (ret == 0 && walk_arg.new_nvlp != NULL) {
		savenew(root);
		update_timestamp(root);
	}

	clear_walk_args();

	return (ret);
}

static char *
find_root_pool()
{
	char *special = get_special("/");
	char *p;

	if (special == NULL)
		return (NULL);

	if (*special == '/') {
		free(special);
		return (NULL);
	}

	if ((p = strchr(special, '/')) != NULL)
		*p = '\0';

	return (special);
}

static error_t
synchronize_BE_menu(void)
{
	struct stat	sb;
	char		cmdline[PATH_MAX];
	char		cksum_line[PATH_MAX];
	filelist_t	flist = {0};
	char		*old_cksum_str;
	char		*old_size_str;
	char		*old_file;
	char		*curr_cksum_str;
	char		*curr_size_str;
	char		*curr_file;
	char		*pool = NULL;
	char		*mntpt = NULL;
	zfs_mnted_t	mnted;
	FILE		*cfp;
	int		found;
	int		ret;
	const char	*fcn = "synchronize_BE_menu()";

	BAM_DPRINTF(("%s: entered. No args\n", fcn));

	/* Check if findroot enabled LU BE */
	if (stat(FINDROOT_INSTALLGRUB, &sb) != 0) {
		BAM_DPRINTF(("%s: not a Live Upgrade BE\n", fcn));
		return (BAM_SUCCESS);
	}

	if (stat(LU_MENU_CKSUM, &sb) != 0) {
		BAM_DPRINTF(("%s: checksum file absent: %s\n",
		    fcn, LU_MENU_CKSUM));
		goto menu_sync;
	}

	cfp = fopen(LU_MENU_CKSUM, "r");
	INJECT_ERROR1("CKSUM_FILE_MISSING", cfp = NULL);
	if (cfp == NULL) {
		bam_error(_("failed to read GRUB menu checksum file: %s\n"),
		    LU_MENU_CKSUM);
		goto menu_sync;
	}
	BAM_DPRINTF(("%s: opened checksum file: %s\n", fcn, LU_MENU_CKSUM));

	found = 0;
	while (s_fgets(cksum_line, sizeof (cksum_line), cfp) != NULL) {
		INJECT_ERROR1("MULTIPLE_CKSUM", found = 1);
		if (found) {
			bam_error(_("multiple checksums for GRUB menu in "
			    "checksum file: %s\n"), LU_MENU_CKSUM);
			(void) fclose(cfp);
			goto menu_sync;
		}
		found = 1;
	}
	BAM_DPRINTF(("%s: read checksum file: %s\n", fcn, LU_MENU_CKSUM));


	old_cksum_str = strtok(cksum_line, " \t");
	old_size_str = strtok(NULL, " \t");
	old_file = strtok(NULL, " \t");

	INJECT_ERROR1("OLD_CKSUM_NULL", old_cksum_str = NULL);
	INJECT_ERROR1("OLD_SIZE_NULL", old_size_str = NULL);
	INJECT_ERROR1("OLD_FILE_NULL", old_file = NULL);
	if (old_cksum_str == NULL || old_size_str == NULL || old_file == NULL) {
		bam_error(_("error parsing GRUB menu checksum file: %s\n"),
		    LU_MENU_CKSUM);
		goto menu_sync;
	}
	BAM_DPRINTF(("%s: parsed checksum file: %s\n", fcn, LU_MENU_CKSUM));

	/* Get checksum of current menu */
	pool = find_root_pool();
	if (pool) {
		mntpt = mount_top_dataset(pool, &mnted);
		if (mntpt == NULL) {
			bam_error(_("failed to mount top dataset for %s\n"),
			    pool);
			free(pool);
			return (BAM_ERROR);
		}
		(void) snprintf(cmdline, sizeof (cmdline), "%s %s%s",
		    CKSUM, mntpt, GRUB_MENU);
	} else {
		(void) snprintf(cmdline, sizeof (cmdline), "%s %s",
		    CKSUM, GRUB_MENU);
	}
	ret = exec_cmd(cmdline, &flist);
	if (pool) {
		(void) umount_top_dataset(pool, mnted, mntpt);
		free(pool);
	}
	INJECT_ERROR1("GET_CURR_CKSUM", ret = 1);
	if (ret != 0) {
		bam_error(_("error generating checksum of GRUB menu\n"));
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: successfully generated checksum\n", fcn));

	INJECT_ERROR1("GET_CURR_CKSUM_OUTPUT", flist.head = NULL);
	if ((flist.head == NULL) || (flist.head != flist.tail)) {
		bam_error(_("bad checksum generated for GRUB menu\n"));
		filelist_free(&flist);
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: generated checksum output valid\n", fcn));

	curr_cksum_str = strtok(flist.head->line, " \t");
	curr_size_str = strtok(NULL, " \t");
	curr_file = strtok(NULL, " \t");

	INJECT_ERROR1("CURR_CKSUM_NULL", curr_cksum_str = NULL);
	INJECT_ERROR1("CURR_SIZE_NULL", curr_size_str = NULL);
	INJECT_ERROR1("CURR_FILE_NULL", curr_file = NULL);
	if (curr_cksum_str == NULL || curr_size_str == NULL ||
	    curr_file == NULL) {
		bam_error(_("error parsing checksum generated "
		    "for GRUB menu\n"));
		filelist_free(&flist);
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: successfully parsed generated checksum\n", fcn));

	if (strcmp(old_cksum_str, curr_cksum_str) == 0 &&
	    strcmp(old_size_str, curr_size_str) == 0 &&
	    strcmp(old_file, curr_file) == 0) {
		filelist_free(&flist);
		BAM_DPRINTF(("%s: no change in checksum of GRUB menu\n", fcn));
		return (BAM_SUCCESS);
	}

	filelist_free(&flist);

	/* cksum doesn't match - the menu has changed */
	BAM_DPRINTF(("%s: checksum of GRUB menu has changed\n", fcn));

menu_sync:
	bam_print(_("propagating updated GRUB menu\n"));

	(void) snprintf(cmdline, sizeof (cmdline),
	    "/bin/sh -c '. %s > /dev/null; %s %s yes > /dev/null'",
	    LULIB, LULIB_PROPAGATE_FILE, GRUB_MENU);
	ret = exec_cmd(cmdline, NULL);
	INJECT_ERROR1("PROPAGATE_MENU", ret = 1);
	if (ret != 0) {
		bam_error(_("error propagating updated GRUB menu\n"));
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: successfully propagated GRUB menu\n", fcn));

	(void) snprintf(cmdline, sizeof (cmdline), "/bin/cp %s %s > /dev/null",
	    GRUB_MENU, GRUB_BACKUP_MENU);
	ret = exec_cmd(cmdline, NULL);
	INJECT_ERROR1("CREATE_BACKUP", ret = 1);
	if (ret != 0) {
		bam_error(_("failed to create backup for GRUB menu: %s\n"),
		    GRUB_BACKUP_MENU);
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: successfully created backup GRUB menu: %s\n",
	    fcn, GRUB_BACKUP_MENU));

	(void) snprintf(cmdline, sizeof (cmdline),
	    "/bin/sh -c '. %s > /dev/null; %s %s no > /dev/null'",
	    LULIB, LULIB_PROPAGATE_FILE, GRUB_BACKUP_MENU);
	ret = exec_cmd(cmdline, NULL);
	INJECT_ERROR1("PROPAGATE_BACKUP", ret = 1);
	if (ret != 0) {
		bam_error(_("error propagating backup GRUB menu: %s\n"),
		    GRUB_BACKUP_MENU);
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: successfully propagated backup GRUB menu: %s\n",
	    fcn, GRUB_BACKUP_MENU));

	(void) snprintf(cmdline, sizeof (cmdline), "%s %s > %s",
	    CKSUM, GRUB_MENU, LU_MENU_CKSUM);
	ret = exec_cmd(cmdline, NULL);
	INJECT_ERROR1("CREATE_CKSUM_FILE", ret = 1);
	if (ret != 0) {
		bam_error(_("failed to write GRUB menu checksum file: %s\n"),
		    LU_MENU_CKSUM);
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: successfully created checksum file: %s\n",
	    fcn, LU_MENU_CKSUM));

	(void) snprintf(cmdline, sizeof (cmdline),
	    "/bin/sh -c '. %s > /dev/null; %s %s no > /dev/null'",
	    LULIB, LULIB_PROPAGATE_FILE, LU_MENU_CKSUM);
	ret = exec_cmd(cmdline, NULL);
	INJECT_ERROR1("PROPAGATE_MENU_CKSUM_FILE", ret = 1);
	if (ret != 0) {
		bam_error(_("error propagating GRUB menu checksum file: %s\n"),
		    LU_MENU_CKSUM);
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: successfully propagated checksum file: %s\n",
	    fcn, LU_MENU_CKSUM));

	return (BAM_SUCCESS);
}

static error_t
update_all(char *root, char *opt)
{
	struct extmnttab mnt;
	struct stat sb;
	FILE *fp;
	char multibt[PATH_MAX];
	char creatram[PATH_MAX];
	error_t ret = BAM_SUCCESS;

	assert(root);
	assert(opt == NULL);

	if (bam_rootlen != 1 || *root != '/') {
		elide_trailing_slash(root, multibt, sizeof (multibt));
		bam_error(_("an alternate root (%s) cannot be used with this "
		    "sub-command\n"), multibt);
		return (BAM_ERROR);
	}

	/*
	 * First update archive for current root
	 */
	if (update_archive(root, opt) != BAM_SUCCESS)
		ret = BAM_ERROR;

	if (ret == BAM_ERROR)
		goto out;

	/*
	 * Now walk the mount table, performing archive update
	 * for all mounted Newboot root filesystems
	 */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"),
		    MNTTAB, strerror(errno));
		ret = BAM_ERROR;
		goto out;
	}

	resetmnttab(fp);

	while (getextmntent(fp, &mnt, sizeof (mnt)) == 0) {
		if (mnt.mnt_special == NULL)
			continue;
		if ((strcmp(mnt.mnt_fstype, MNTTYPE_ZFS) != 0) &&
		    (strncmp(mnt.mnt_special, "/dev/", strlen("/dev/")) != 0))
			continue;
		if (strcmp(mnt.mnt_mountp, "/") == 0)
			continue;

		(void) snprintf(creatram, sizeof (creatram), "%s/%s",
		    mnt.mnt_mountp, CREATE_RAMDISK);

		if (stat(creatram, &sb) == -1)
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
		if ((get_boot_cap(rootbuf) != BAM_SUCCESS) ||
		    (update_archive(rootbuf, opt) != BAM_SUCCESS))
			ret = BAM_ERROR;
	}

	(void) fclose(fp);

out:
	/*
	 * We no longer use biosdev for Live Upgrade. Hence
	 * there is no need to defer (to shutdown time) any fdisk
	 * updates
	 */
	if (stat(GRUB_fdisk, &sb) == 0 || stat(GRUB_fdisk_target, &sb) == 0) {
		bam_error(_("Deferred FDISK update file(s) found: %s, %s. "
		    "Not supported.\n"), GRUB_fdisk, GRUB_fdisk_target);
	}

	/*
	 * If user has updated menu in current BE, propagate the
	 * updates to all BEs.
	 */
	if (sync_menu && synchronize_BE_menu() != BAM_SUCCESS)
		ret = BAM_ERROR;

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

void
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
	const char *fcn = "boot_entry_new()";

	assert(mp);
	assert(start);
	assert(end);

	ent = s_calloc(1, sizeof (entry_t));
	BAM_DPRINTF(("%s: new boot entry alloced\n", fcn));
	ent->start = start;
	ent->end = end;

	if (mp->entries == NULL) {
		mp->entries = ent;
		BAM_DPRINTF(("%s: (first) new boot entry created\n", fcn));
		return (ent);
	}

	prev = mp->entries;
	while (prev->next)
		prev = prev->next;
	prev->next = ent;
	ent->prev = prev;
	BAM_DPRINTF(("%s: new boot entry linked in\n", fcn));
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
	int			ret;
	const char		*fcn = "check_cmd()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, arg, str));

	if (cmd != NULL) {
		if ((strcmp(cmd, menu_cmds[which]) != 0) &&
		    (strcmp(cmd, menu_cmds[which + 1]) != 0)) {
			BAM_DPRINTF(("%s: command %s does not match %s\n",
			    fcn, cmd, menu_cmds[which]));
			return (0);
		}
		ret = (strstr(arg, str) != NULL);
	} else
		ret = 0;

	if (ret) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}

	return (ret);
}

static error_t
kernel_parser(entry_t *entry, char *cmd, char *arg, int linenum)
{
	const char		*fcn  = "kernel_parser()";

	assert(entry);
	assert(cmd);
	assert(arg);

	if (strcmp(cmd, menu_cmds[KERNEL_CMD]) != 0 &&
	    strcmp(cmd, menu_cmds[KERNEL_DOLLAR_CMD]) != 0) {
		BAM_DPRINTF(("%s: not a kernel command: %s\n", fcn, cmd));
		return (BAM_ERROR);
	}

	if (strncmp(arg, DIRECT_BOOT_32, sizeof (DIRECT_BOOT_32) - 1) == 0) {
		BAM_DPRINTF(("%s: setting DBOOT|DBOOT_32 flag: %s\n",
		    fcn, arg));
		entry->flags |= BAM_ENTRY_DBOOT | BAM_ENTRY_32BIT;
	} else if (strncmp(arg, DIRECT_BOOT_KERNEL,
	    sizeof (DIRECT_BOOT_KERNEL) - 1) == 0) {
		BAM_DPRINTF(("%s: setting DBOOT flag: %s\n", fcn, arg));
		entry->flags |= BAM_ENTRY_DBOOT;
	} else if (strncmp(arg, DIRECT_BOOT_64,
	    sizeof (DIRECT_BOOT_64) - 1) == 0) {
		BAM_DPRINTF(("%s: setting DBOOT|DBOOT_64 flag: %s\n",
		    fcn, arg));
		entry->flags |= BAM_ENTRY_DBOOT | BAM_ENTRY_64BIT;
	} else if (strncmp(arg, DIRECT_BOOT_FAILSAFE_KERNEL,
	    sizeof (DIRECT_BOOT_FAILSAFE_KERNEL) - 1) == 0) {
		BAM_DPRINTF(("%s: setting DBOOT|DBOOT_FAILSAFE flag: %s\n",
		    fcn, arg));
		entry->flags |= BAM_ENTRY_DBOOT | BAM_ENTRY_FAILSAFE;
	} else if (strncmp(arg, DIRECT_BOOT_FAILSAFE_32,
	    sizeof (DIRECT_BOOT_FAILSAFE_32) - 1) == 0) {
		BAM_DPRINTF(("%s: setting DBOOT|DBOOT_FAILSAFE|DBOOT_32 "
		    "flag: %s\n", fcn, arg));
		entry->flags |= BAM_ENTRY_DBOOT | BAM_ENTRY_FAILSAFE
		    | BAM_ENTRY_32BIT;
	} else if (strncmp(arg, DIRECT_BOOT_FAILSAFE_64,
	    sizeof (DIRECT_BOOT_FAILSAFE_64) - 1) == 0) {
		BAM_DPRINTF(("%s: setting DBOOT|DBOOT_FAILSAFE|DBOOT_64 "
		    "flag: %s\n", fcn, arg));
		entry->flags |= BAM_ENTRY_DBOOT | BAM_ENTRY_FAILSAFE
		    | BAM_ENTRY_64BIT;
	} else if (strncmp(arg, MULTI_BOOT, sizeof (MULTI_BOOT) - 1) == 0) {
		BAM_DPRINTF(("%s: setting MULTIBOOT flag: %s\n", fcn, arg));
		entry->flags |= BAM_ENTRY_MULTIBOOT;
	} else if (strncmp(arg, MULTI_BOOT_FAILSAFE,
	    sizeof (MULTI_BOOT_FAILSAFE) - 1) == 0) {
		BAM_DPRINTF(("%s: setting MULTIBOOT|MULTIBOOT_FAILSAFE "
		    "flag: %s\n", fcn, arg));
		entry->flags |= BAM_ENTRY_MULTIBOOT | BAM_ENTRY_FAILSAFE;
	} else if (strstr(arg, XEN_KERNEL_SUBSTR)) {
		BAM_DPRINTF(("%s: setting XEN HV flag: %s\n", fcn, arg));
		entry->flags |= BAM_ENTRY_HV;
	} else if (!(entry->flags & (BAM_ENTRY_BOOTADM|BAM_ENTRY_LU))) {
		BAM_DPRINTF(("%s: is HAND kernel flag: %s\n", fcn, arg));
		return (BAM_ERROR);
	} else if (strncmp(arg, KERNEL_PREFIX, strlen(KERNEL_PREFIX)) == 0 &&
	    strstr(arg, UNIX_SPACE)) {
		entry->flags |= BAM_ENTRY_DBOOT | BAM_ENTRY_32BIT;
	} else if (strncmp(arg, KERNEL_PREFIX, strlen(KERNEL_PREFIX)) == 0 &&
	    strstr(arg, AMD_UNIX_SPACE)) {
		entry->flags |= BAM_ENTRY_DBOOT | BAM_ENTRY_64BIT;
	} else {
		BAM_DPRINTF(("%s: is UNKNOWN kernel entry: %s\n", fcn, arg));
		bam_error(_("kernel command on line %d not recognized.\n"),
		    linenum);
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

static error_t
module_parser(entry_t *entry, char *cmd, char *arg, int linenum)
{
	const char		*fcn = "module_parser()";

	assert(entry);
	assert(cmd);
	assert(arg);

	if (strcmp(cmd, menu_cmds[MODULE_CMD]) != 0 &&
	    strcmp(cmd, menu_cmds[MODULE_DOLLAR_CMD]) != 0) {
		BAM_DPRINTF(("%s: not module cmd: %s\n", fcn, cmd));
		return (BAM_ERROR);
	}

	if (strcmp(arg, DIRECT_BOOT_ARCHIVE) == 0 ||
	    strcmp(arg, DIRECT_BOOT_ARCHIVE_32) == 0 ||
	    strcmp(arg, DIRECT_BOOT_ARCHIVE_64) == 0 ||
	    strcmp(arg, MULTIBOOT_ARCHIVE) == 0 ||
	    strcmp(arg, FAILSAFE_ARCHIVE) == 0 ||
	    strcmp(arg, FAILSAFE_ARCHIVE_32) == 0 ||
	    strcmp(arg, FAILSAFE_ARCHIVE_64) == 0 ||
	    strcmp(arg, XEN_KERNEL_MODULE_LINE) == 0 ||
	    strcmp(arg, XEN_KERNEL_MODULE_LINE_ZFS) == 0) {
		BAM_DPRINTF(("%s: bootadm or LU module cmd: %s\n", fcn, arg));
		return (BAM_SUCCESS);
	} else if (!(entry->flags & BAM_ENTRY_BOOTADM) &&
	    !(entry->flags & BAM_ENTRY_LU)) {
		/* don't emit warning for hand entries */
		BAM_DPRINTF(("%s: is HAND module: %s\n", fcn, arg));
		return (BAM_ERROR);
	} else {
		BAM_DPRINTF(("%s: is UNKNOWN module: %s\n", fcn, arg));
		bam_error(_("module command on line %d not recognized.\n"),
		    linenum);
		return (BAM_ERROR);
	}
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
	static int is_libbe_ent = 0;

	line_t	*lp;
	char *cmd, *sep, *arg;
	char save, *cp, *line;
	menu_flag_t flag = BAM_INVALID;
	const char *fcn = "line_parser()";

	cmd = NULL;
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
		} else if (strstr(arg, BAM_LIBBE_FTR) != NULL) {
			is_libbe_ent = 1;
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
			curr_ent->flags |= BAM_ENTRY_BOOTADM;
			BAM_DPRINTF(("%s: is bootadm(1M) entry: %s\n",
			    fcn, arg));
		} else {
			curr_ent = boot_entry_new(mp, lp, lp);
			if (in_liveupgrade) {
				curr_ent->flags |= BAM_ENTRY_LU;
				BAM_DPRINTF(("%s: is LU entry: %s\n",
				    fcn, arg));
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
				if (strcmp(cmd, menu_cmds[ROOT_CMD]) == 0) {
					BAM_DPRINTF(("%s: setting ROOT: %s\n",
					    fcn, arg));
					curr_ent->flags |= BAM_ENTRY_ROOT;
				} else if (strcmp(cmd, menu_cmds[FINDROOT_CMD])
				    == 0) {
					BAM_DPRINTF(("%s: setting "
					    "FINDROOT: %s\n", fcn, arg));
					curr_ent->flags |= BAM_ENTRY_FINDROOT;
				} else if (strcmp(cmd,
				    menu_cmds[CHAINLOADER_CMD]) == 0) {
					BAM_DPRINTF(("%s: setting "
					    "CHAINLOADER: %s\n", fcn, arg));
					curr_ent->flags |=
					    BAM_ENTRY_CHAINLOADER;
				} else if (kernel_parser(curr_ent, cmd, arg,
				    lp->lineNum) != BAM_SUCCESS) {
					(void) module_parser(curr_ent, cmd,
					    arg, lp->lineNum);
				}
			}
		}
	}

	/* record default, old default, and entry line ranges */
	if (lp->flags == BAM_GLOBAL && lp->cmd != NULL &&
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
	    ((strcmp(lp->arg, BAM_BOOTADM_FTR) == 0) || is_libbe_ent))) {
		if (is_libbe_ent) {
			curr_ent->flags |= BAM_ENTRY_LIBBE;
			is_libbe_ent = 0;
		}

		boot_entry_addline(curr_ent, lp);
	}
	append_line(mp, lp);

	prev = lp;
}

void
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
		if (lp->entryNum == ENTRY_INIT && lp->cmd != NULL &&
		    strcmp(lp->cmd, menu_cmds[DEFAULT_CMD]) == 0 &&
		    lp->arg) {
			old_default_value = atoi(lp->arg);
			default_lp = lp;
		}

		/*
		 * If not a booting entry, nothing else to fix for this
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
		if (lp->cmd != NULL &&
		    strcmp(lp->cmd, menu_cmds[TITLE_CMD]) == 0) {
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
		free(mp);
		return (NULL);
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
		bam_error(_("failed to close file: %s: %s\n"), menu_path,
		    strerror(errno));
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
		bam_error(_("invalid option: %s\n"), opt);
		free(opt_dup);
		return (BAM_ERROR);
	}

	*eq = '\0';
	if (entry && strcmp(opt_dup, OPT_ENTRY_NUM) == 0) {
		assert(mp->end);
		entryNum = s_strtol(eq + 1);
		if (entryNum < 0 || entryNum > mp->end->entryNum) {
			bam_error(_("invalid boot entry number: %s\n"), eq + 1);
			free(opt_dup);
			return (BAM_ERROR);
		}
		*entry = entryNum;
	} else if (title && strcmp(opt_dup, menu_cmds[TITLE_CMD]) == 0) {
		*title = opt + (eq - opt_dup) + 1;
	} else {
		bam_error(_("invalid option: %s\n"), opt);
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

	/* opt is optional */
	BAM_DPRINTF(("%s: entered. args: %s %s\n", "list_entry", menu_path,
	    opt ? opt : "<NULL>"));

	if (mp->start == NULL) {
		bam_error(_("menu file not found: %s\n"), menu_path);
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
			bam_print(_("%d %s\n"), lp->entryNum,
			    lp->arg);
			found = 1;
			continue;
		}
		if (entry != ENTRY_INIT && lp->entryNum == entry) {
			bam_print(_("%s\n"), lp->line);
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
			bam_print(_("%s\n"), lp->line);
			entry = lp->entryNum;
			found = 1;
			continue;
		}
	}

	if (!found) {
		bam_error(_("no matching entry found\n"));
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

int
add_boot_entry(menu_t *mp,
    char *title,
    char *findroot,
    char *kernel,
    char *mod_kernel,
    char *module,
    char *bootfs)
{
	int		lineNum;
	int		entryNum;
	char		linebuf[BAM_MAXLINE];
	menu_cmd_t	k_cmd;
	menu_cmd_t	m_cmd;
	const char	*fcn = "add_boot_entry()";

	assert(mp);

	INJECT_ERROR1("ADD_BOOT_ENTRY_FINDROOT_NULL", findroot = NULL);
	if (findroot == NULL) {
		bam_error(_("can't find argument for findroot command\n"));
		return (BAM_ERROR);
	}

	if (title == NULL) {
		title = "Solaris";	/* default to Solaris */
	}
	if (kernel == NULL) {
		bam_error(_("missing suboption: %s\n"), menu_cmds[KERNEL_CMD]);
		return (BAM_ERROR);
	}
	if (module == NULL) {
		if (bam_direct != BAM_DIRECT_DBOOT) {
			bam_error(_("missing suboption: %s\n"),
			    menu_cmds[MODULE_CMD]);
			return (BAM_ERROR);
		}

		/* Figure the commands out from the kernel line */
		if (strstr(kernel, "$ISADIR") != NULL) {
			module = DIRECT_BOOT_ARCHIVE;
		} else if (strstr(kernel, "amd64") != NULL) {
			module = DIRECT_BOOT_ARCHIVE_64;
		} else {
			module = DIRECT_BOOT_ARCHIVE_32;
		}
	}

	k_cmd = KERNEL_DOLLAR_CMD;
	m_cmd = MODULE_DOLLAR_CMD;

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

	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[FINDROOT_CMD], menu_cmds[SEP_CMD], findroot);
	line_parser(mp, linebuf, &lineNum, &entryNum);
	BAM_DPRINTF(("%s: findroot added: line#: %d: entry#: %d\n",
	    fcn, lineNum, entryNum));

	if (bootfs != NULL) {
		(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
		    menu_cmds[BOOTFS_CMD], menu_cmds[SEP_CMD], bootfs);
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

error_t
delete_boot_entry(menu_t *mp, int entryNum, int quiet)
{
	line_t		*lp;
	line_t		*freed;
	entry_t		*ent;
	entry_t		*tmp;
	int		deleted = 0;
	const char	*fcn = "delete_boot_entry()";

	assert(entryNum != ENTRY_INIT);

	tmp = NULL;

	ent = mp->entries;
	while (ent) {
		lp = ent->start;

		/*
		 * Check entry number and make sure it's a modifiable entry.
		 *
		 * Guidelines:
		 *	+ We can modify a bootadm-created entry
		 *	+ We can modify a libbe-created entry
		 */
		if ((lp->flags != BAM_COMMENT &&
		    (((ent->flags & BAM_ENTRY_LIBBE) == 0) &&
		    strcmp(lp->arg, BAM_BOOTADM_HDR) != 0)) ||
		    (entryNum != ALL_ENTRIES && lp->entryNum != entryNum)) {
			ent = ent->next;
			continue;
		}

		/* free the entry content */
		do {
			freed = lp;
			lp = lp->next;	/* prev stays the same */
			BAM_DPRINTF(("%s: freeing line: %d\n",
			    fcn, freed->lineNum));
			unlink_line(mp, freed);
			line_free(freed);
		} while (freed != ent->end);

		/* free the entry_t structure */
		assert(tmp == NULL);
		tmp = ent;
		ent = ent->next;
		if (tmp->prev)
			tmp->prev->next = ent;
		else
			mp->entries = ent;
		if (ent)
			ent->prev = tmp->prev;
		BAM_DPRINTF(("%s: freeing entry: %d\n", fcn, tmp->entryNum));
		free(tmp);
		tmp = NULL;
		deleted = 1;
	}

	assert(tmp == NULL);

	if (!deleted && entryNum != ALL_ENTRIES) {
		if (quiet == DBE_PRINTERR)
			bam_error(_("no matching bootadm entry found\n"));
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
delete_all_entries(menu_t *mp, char *dummy, char *opt)
{
	assert(mp);
	assert(dummy == NULL);
	assert(opt == NULL);

	BAM_DPRINTF(("%s: entered. No args\n", "delete_all_entries"));

	if (mp->start == NULL) {
		bam_print(_("the GRUB menu is empty\n"));
		return (BAM_SUCCESS);
	}

	if (delete_boot_entry(mp, ALL_ENTRIES, DBE_PRINTERR) != BAM_SUCCESS) {
		return (BAM_ERROR);
	}

	return (BAM_WRITE);
}

static FILE *
create_diskmap(char *osroot)
{
	FILE *fp;
	char cmd[PATH_MAX + 16];
	char path[PATH_MAX];
	const char *fcn = "create_diskmap()";

	/* make sure we have a map file */
	fp = fopen(GRUBDISK_MAP, "r");
	if (fp == NULL) {
		int	ret;

		ret = snprintf(path, sizeof (path), "%s/%s", osroot,
		    CREATE_DISKMAP);
		if (ret >= sizeof (path)) {
			bam_error(_("unable to create path on mountpoint %s, "
			    "path too long\n"), osroot);
			return (NULL);
		}
		if (is_safe_exec(path) == BAM_ERROR)
			return (NULL);

		(void) snprintf(cmd, sizeof (cmd),
		    "%s/%s > /dev/null", osroot, CREATE_DISKMAP);
		if (exec_cmd(cmd, NULL) != 0)
			return (NULL);
		fp = fopen(GRUBDISK_MAP, "r");
		INJECT_ERROR1("DISKMAP_CREATE_FAIL", fp = NULL);
		if (fp) {
			BAM_DPRINTF(("%s: created diskmap file: %s\n",
			    fcn, GRUBDISK_MAP));
		} else {
			BAM_DPRINTF(("%s: FAILED to create diskmap file: %s\n",
			    fcn, GRUBDISK_MAP));
		}
	}
	return (fp);
}

#define	SECTOR_SIZE	512

static int
get_partition(char *device)
{
	int i, fd, is_pcfs, partno = PARTNO_NOTFOUND;
	struct mboot *mboot;
	char boot_sect[SECTOR_SIZE];
	char *wholedisk, *slice;
#ifdef i386
	ext_part_t *epp;
	uint32_t secnum, numsec;
	int rval, pno, ext_partno = PARTNO_NOTFOUND;
#endif

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
	if (fd == -1 || read(fd, boot_sect, SECTOR_SIZE) != SECTOR_SIZE) {
		return (partno);
	}
	(void) close(fd);

#ifdef i386
	/* Read/Initialize extended partition information */
	if ((rval = libfdisk_init(&epp, wholedisk, NULL, FDISK_READ_DISK))
	    != FDISK_SUCCESS) {
		switch (rval) {
			/*
			 * FDISK_EBADLOGDRIVE and FDISK_ENOLOGDRIVE can
			 * be considered as soft errors and hence
			 * we do not return
			 */
			case FDISK_EBADLOGDRIVE:
				break;
			case FDISK_ENOLOGDRIVE:
				break;
			case FDISK_EBADMAGIC:
				/*FALLTHROUGH*/
			default:
				free(wholedisk);
				libfdisk_fini(&epp);
				return (partno);
		}
	}
#endif
	free(wholedisk);

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
			if (part->systid == EFI_PMBR) {
				partno = PARTNO_EFI;
				break;
			}

#ifdef i386
			if ((part->systid == SUNIXOS &&
			    (fdisk_is_linux_swap(epp, part->relsect,
			    NULL) != 0)) || part->systid == SUNIXOS2) {
#else
			if (part->systid == SUNIXOS ||
			    part->systid == SUNIXOS2) {
#endif
				partno = i;
				break;
			}

#ifdef i386
			if (fdisk_is_dos_extended(part->systid))
				ext_partno = i;
#endif
		}
	}
#ifdef i386
	/* If no primary solaris partition, check extended partition */
	if ((partno == PARTNO_NOTFOUND) && (ext_partno != PARTNO_NOTFOUND)) {
		rval = fdisk_get_solaris_part(epp, &pno, &secnum, &numsec);
		if (rval == FDISK_SUCCESS) {
			partno = pno - 1;
		}
	}
	libfdisk_fini(&epp);
#endif
	return (partno);
}

char *
get_grubroot(char *osroot, char *osdev, char *menu_root)
{
	char		*grubroot;	/* (hd#,#,#) */
	char		*slice;
	char		*grubhd = NULL;
	int		fdiskpart;
	int		found = 0;
	char		*devname;
	char		*ctdname = strstr(osdev, "dsk/");
	char		linebuf[PATH_MAX];
	FILE		*fp;

	INJECT_ERROR1("GRUBROOT_INVALID_OSDEV", ctdname = NULL);
	if (ctdname == NULL) {
		bam_error(_("not a /dev/[r]dsk name: %s\n"), osdev);
		return (NULL);
	}

	if (menu_root && !menu_on_bootdisk(osroot, menu_root)) {
		/* menu bears no resemblance to our reality */
		bam_error(_("cannot get (hd?,?,?) for menu. menu not on "
		    "bootdisk: %s\n"), osdev);
		return (NULL);
	}

	ctdname += strlen("dsk/");
	slice = strrchr(ctdname, 's');
	if (slice)
		*slice = '\0';

	fp = create_diskmap(osroot);
	if (fp == NULL) {
		bam_error(_("create_diskmap command failed for OS root: %s.\n"),
		    osroot);
		return (NULL);
	}

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

	(void) fclose(fp);
	fp = NULL;

	INJECT_ERROR1("GRUBROOT_BIOSDEV_FAIL", found = 0);
	if (found == 0) {
		bam_error(_("not using biosdev command for disk: %s.\n"),
		    osdev);
		return (NULL);
	}

	fdiskpart = get_partition(osdev);
	INJECT_ERROR1("GRUBROOT_FDISK_FAIL", fdiskpart = PARTNO_NOTFOUND);
	if (fdiskpart == PARTNO_NOTFOUND) {
		bam_error(_("failed to determine fdisk partition: %s\n"),
		    osdev);
		return (NULL);
	}

	grubroot = s_calloc(1, 10);
	if (fdiskpart == PARTNO_EFI) {
		fdiskpart = atoi(&slice[1]);
		slice = NULL;
	}

	if (slice) {
		(void) snprintf(grubroot, 10, "(hd%s,%d,%c)",
		    grubhd, fdiskpart, slice[1] + 'a' - '0');
	} else
		(void) snprintf(grubroot, 10, "(hd%s,%d)",
		    grubhd, fdiskpart);

	assert(fp == NULL);
	assert(strncmp(grubroot, "(hd", strlen("(hd")) == 0);
	return (grubroot);
}

static char *
find_primary_common(char *mntpt, char *fstype)
{
	char		signdir[PATH_MAX];
	char		tmpsign[MAXNAMELEN + 1];
	char		*lu;
	char		*ufs;
	char		*zfs;
	DIR		*dirp = NULL;
	struct dirent	*entp;
	struct stat	sb;
	const char	*fcn = "find_primary_common()";

	(void) snprintf(signdir, sizeof (signdir), "%s/%s",
	    mntpt, GRUBSIGN_DIR);

	if (stat(signdir, &sb) == -1) {
		BAM_DPRINTF(("%s: no sign dir: %s\n", fcn, signdir));
		return (NULL);
	}

	dirp = opendir(signdir);
	INJECT_ERROR1("SIGNDIR_OPENDIR_FAIL", dirp = NULL);
	if (dirp == NULL) {
		bam_error(_("opendir of %s failed: %s\n"), signdir,
		    strerror(errno));
		return (NULL);
	}

	ufs = zfs = lu = NULL;

	while ((entp = readdir(dirp)) != NULL) {
		if (strcmp(entp->d_name, ".") == 0 ||
		    strcmp(entp->d_name, "..") == 0)
			continue;

		(void) snprintf(tmpsign, sizeof (tmpsign), "%s", entp->d_name);

		if (lu == NULL &&
		    strncmp(tmpsign, GRUBSIGN_LU_PREFIX,
		    strlen(GRUBSIGN_LU_PREFIX)) == 0) {
			lu = s_strdup(tmpsign);
		}

		if (ufs == NULL &&
		    strncmp(tmpsign, GRUBSIGN_UFS_PREFIX,
		    strlen(GRUBSIGN_UFS_PREFIX)) == 0) {
			ufs = s_strdup(tmpsign);
		}

		if (zfs == NULL &&
		    strncmp(tmpsign, GRUBSIGN_ZFS_PREFIX,
		    strlen(GRUBSIGN_ZFS_PREFIX)) == 0) {
			zfs = s_strdup(tmpsign);
		}
	}

	BAM_DPRINTF(("%s: existing primary signs: zfs=%s ufs=%s lu=%s\n", fcn,
	    zfs ? zfs : "NULL",
	    ufs ? ufs : "NULL",
	    lu ? lu : "NULL"));

	if (dirp) {
		(void) closedir(dirp);
		dirp = NULL;
	}

	if (strcmp(fstype, "ufs") == 0 && zfs) {
		bam_error(_("found mismatched boot signature %s for "
		    "filesystem type: %s.\n"), zfs, "ufs");
		free(zfs);
		zfs = NULL;
	} else if (strcmp(fstype, "zfs") == 0 && ufs) {
		bam_error(_("found mismatched boot signature %s for "
		    "filesystem type: %s.\n"), ufs, "zfs");
		free(ufs);
		ufs = NULL;
	}

	assert(dirp == NULL);

	/* For now, we let Live Upgrade take care of its signature itself */
	if (lu) {
		BAM_DPRINTF(("%s: feeing LU sign: %s\n", fcn, lu));
		free(lu);
		lu = NULL;
	}

	return (zfs ? zfs : ufs);
}

static char *
find_backup_common(char *mntpt, char *fstype)
{
	FILE		*bfp = NULL;
	char		tmpsign[MAXNAMELEN + 1];
	char		backup[PATH_MAX];
	char		*ufs;
	char		*zfs;
	char		*lu;
	int		error;
	const char	*fcn = "find_backup_common()";

	/*
	 * We didn't find it in the primary directory.
	 * Look at the backup
	 */
	(void) snprintf(backup, sizeof (backup), "%s%s",
	    mntpt, GRUBSIGN_BACKUP);

	bfp = fopen(backup, "r");
	if (bfp == NULL) {
		error = errno;
		if (bam_verbose) {
			bam_error(_("failed to open file: %s: %s\n"),
			    backup, strerror(error));
		}
		BAM_DPRINTF(("%s: failed to open %s: %s\n",
		    fcn, backup, strerror(error)));
		return (NULL);
	}

	ufs = zfs = lu = NULL;

	while (s_fgets(tmpsign, sizeof (tmpsign), bfp) != NULL) {

		if (lu == NULL &&
		    strncmp(tmpsign, GRUBSIGN_LU_PREFIX,
		    strlen(GRUBSIGN_LU_PREFIX)) == 0) {
			lu = s_strdup(tmpsign);
		}

		if (ufs == NULL &&
		    strncmp(tmpsign, GRUBSIGN_UFS_PREFIX,
		    strlen(GRUBSIGN_UFS_PREFIX)) == 0) {
			ufs = s_strdup(tmpsign);
		}

		if (zfs == NULL &&
		    strncmp(tmpsign, GRUBSIGN_ZFS_PREFIX,
		    strlen(GRUBSIGN_ZFS_PREFIX)) == 0) {
			zfs = s_strdup(tmpsign);
		}
	}

	BAM_DPRINTF(("%s: existing backup signs: zfs=%s ufs=%s lu=%s\n", fcn,
	    zfs ? zfs : "NULL",
	    ufs ? ufs : "NULL",
	    lu ? lu : "NULL"));

	if (bfp) {
		(void) fclose(bfp);
		bfp = NULL;
	}

	if (strcmp(fstype, "ufs") == 0 && zfs) {
		bam_error(_("found mismatched boot signature %s for "
		    "filesystem type: %s.\n"), zfs, "ufs");
		free(zfs);
		zfs = NULL;
	} else if (strcmp(fstype, "zfs") == 0 && ufs) {
		bam_error(_("found mismatched boot signature %s for "
		    "filesystem type: %s.\n"), ufs, "zfs");
		free(ufs);
		ufs = NULL;
	}

	assert(bfp == NULL);

	/* For now, we let Live Upgrade take care of its signature itself */
	if (lu) {
		BAM_DPRINTF(("%s: feeing LU sign: %s\n", fcn, lu));
		free(lu);
		lu = NULL;
	}

	return (zfs ? zfs : ufs);
}

static char *
find_ufs_existing(char *osroot)
{
	char		*sign;
	const char	*fcn = "find_ufs_existing()";

	sign = find_primary_common(osroot, "ufs");
	if (sign == NULL) {
		sign = find_backup_common(osroot, "ufs");
		BAM_DPRINTF(("%s: existing backup sign: %s\n", fcn,
		    sign ? sign : "NULL"));
	} else {
		BAM_DPRINTF(("%s: existing primary sign: %s\n", fcn, sign));
	}

	return (sign);
}

char *
get_mountpoint(char *special, char *fstype)
{
	FILE		*mntfp;
	struct mnttab	mp = {0};
	struct mnttab	mpref = {0};
	int		error;
	int		ret;
	const char	*fcn = "get_mountpoint()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, special, fstype));

	mntfp = fopen(MNTTAB, "r");
	error = errno;
	INJECT_ERROR1("MNTTAB_ERR_GET_MNTPT", mntfp = NULL);
	if (mntfp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"),
		    MNTTAB, strerror(error));
		return (NULL);
	}

	mpref.mnt_special = special;
	mpref.mnt_fstype = fstype;

	ret = getmntany(mntfp, &mp, &mpref);
	INJECT_ERROR1("GET_MOUNTPOINT_MNTANY", ret = 1);
	if (ret != 0) {
		(void) fclose(mntfp);
		BAM_DPRINTF(("%s: no mount-point for special=%s and "
		    "fstype=%s\n", fcn, special, fstype));
		return (NULL);
	}
	(void) fclose(mntfp);

	assert(mp.mnt_mountp);

	BAM_DPRINTF(("%s: returning mount-point for special %s: %s\n",
	    fcn, special, mp.mnt_mountp));

	return (s_strdup(mp.mnt_mountp));
}

/*
 * Mounts a "legacy" top dataset (if needed)
 * Returns:	The mountpoint of the legacy top dataset or NULL on error
 * 		mnted returns one of the above values defined for zfs_mnted_t
 */
static char *
mount_legacy_dataset(char *pool, zfs_mnted_t *mnted)
{
	char		cmd[PATH_MAX];
	char		tmpmnt[PATH_MAX];
	filelist_t	flist = {0};
	char		*is_mounted;
	struct stat	sb;
	int		ret;
	const char	*fcn = "mount_legacy_dataset()";

	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, pool));

	*mnted = ZFS_MNT_ERROR;

	(void) snprintf(cmd, sizeof (cmd),
	    "/sbin/zfs get -Ho value mounted %s",
	    pool);

	ret = exec_cmd(cmd, &flist);
	INJECT_ERROR1("Z_MOUNT_LEG_GET_MOUNTED_CMD", ret = 1);
	if (ret != 0) {
		bam_error(_("failed to determine mount status of ZFS "
		    "pool %s\n"), pool);
		return (NULL);
	}

	INJECT_ERROR1("Z_MOUNT_LEG_GET_MOUNTED_OUT", flist.head = NULL);
	if ((flist.head == NULL) || (flist.head != flist.tail)) {
		bam_error(_("ZFS pool %s has bad mount status\n"), pool);
		filelist_free(&flist);
		return (NULL);
	}

	is_mounted = strtok(flist.head->line, " \t\n");
	INJECT_ERROR1("Z_MOUNT_LEG_GET_MOUNTED_STRTOK_YES", is_mounted = "yes");
	INJECT_ERROR1("Z_MOUNT_LEG_GET_MOUNTED_STRTOK_NO", is_mounted = "no");
	if (strcmp(is_mounted, "no") != 0) {
		filelist_free(&flist);
		*mnted = LEGACY_ALREADY;
		/* get_mountpoint returns a strdup'ed string */
		BAM_DPRINTF(("%s: legacy pool %s already mounted\n",
		    fcn, pool));
		return (get_mountpoint(pool, "zfs"));
	}

	filelist_free(&flist);

	/*
	 * legacy top dataset is not mounted. Mount it now
	 * First create a mountpoint.
	 */
	(void) snprintf(tmpmnt, sizeof (tmpmnt), "%s.%d",
	    ZFS_LEGACY_MNTPT, getpid());

	ret = stat(tmpmnt, &sb);
	if (ret == -1) {
		BAM_DPRINTF(("%s: legacy pool %s mount-point %s absent\n",
		    fcn, pool, tmpmnt));
		ret = mkdirp(tmpmnt, DIR_PERMS);
		INJECT_ERROR1("Z_MOUNT_TOP_LEG_MNTPT_MKDIRP", ret = -1);
		if (ret == -1) {
			bam_error(_("mkdir of %s failed: %s\n"), tmpmnt,
			    strerror(errno));
			return (NULL);
		}
	} else {
		BAM_DPRINTF(("%s: legacy pool %s mount-point %s is already "
		    "present\n", fcn, pool, tmpmnt));
	}

	(void) snprintf(cmd, sizeof (cmd),
	    "/sbin/mount -F zfs %s %s",
	    pool, tmpmnt);

	ret = exec_cmd(cmd, NULL);
	INJECT_ERROR1("Z_MOUNT_TOP_LEG_MOUNT_CMD", ret = 1);
	if (ret != 0) {
		bam_error(_("mount of ZFS pool %s failed\n"), pool);
		(void) rmdir(tmpmnt);
		return (NULL);
	}

	*mnted = LEGACY_MOUNTED;
	BAM_DPRINTF(("%s: legacy pool %s successfully mounted at %s\n",
	    fcn, pool, tmpmnt));
	return (s_strdup(tmpmnt));
}

/*
 * Mounts the top dataset (if needed)
 * Returns:	The mountpoint of the top dataset or NULL on error
 * 		mnted returns one of the above values defined for zfs_mnted_t
 */
char *
mount_top_dataset(char *pool, zfs_mnted_t *mnted)
{
	char		cmd[PATH_MAX];
	filelist_t	flist = {0};
	char		*is_mounted;
	char		*mntpt;
	char		*zmntpt;
	int		ret;
	const char	*fcn = "mount_top_dataset()";

	*mnted = ZFS_MNT_ERROR;

	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, pool));

	/*
	 * First check if the top dataset is a "legacy" dataset
	 */
	(void) snprintf(cmd, sizeof (cmd),
	    "/sbin/zfs get -Ho value mountpoint %s",
	    pool);
	ret = exec_cmd(cmd, &flist);
	INJECT_ERROR1("Z_MOUNT_TOP_GET_MNTPT", ret = 1);
	if (ret != 0) {
		bam_error(_("failed to determine mount point of ZFS pool %s\n"),
		    pool);
		return (NULL);
	}

	if (flist.head && (flist.head == flist.tail)) {
		char *legacy = strtok(flist.head->line, " \t\n");
		if (legacy && strcmp(legacy, "legacy") == 0) {
			filelist_free(&flist);
			BAM_DPRINTF(("%s: is legacy, pool=%s\n", fcn, pool));
			return (mount_legacy_dataset(pool, mnted));
		}
	}

	filelist_free(&flist);

	BAM_DPRINTF(("%s: is *NOT* legacy, pool=%s\n", fcn, pool));

	(void) snprintf(cmd, sizeof (cmd),
	    "/sbin/zfs get -Ho value mounted %s",
	    pool);

	ret = exec_cmd(cmd, &flist);
	INJECT_ERROR1("Z_MOUNT_TOP_NONLEG_GET_MOUNTED", ret = 1);
	if (ret != 0) {
		bam_error(_("failed to determine mount status of ZFS "
		    "pool %s\n"), pool);
		return (NULL);
	}

	INJECT_ERROR1("Z_MOUNT_TOP_NONLEG_GET_MOUNTED_VAL", flist.head = NULL);
	if ((flist.head == NULL) || (flist.head != flist.tail)) {
		bam_error(_("ZFS pool %s has bad mount status\n"), pool);
		filelist_free(&flist);
		return (NULL);
	}

	is_mounted = strtok(flist.head->line, " \t\n");
	INJECT_ERROR1("Z_MOUNT_TOP_NONLEG_GET_MOUNTED_YES", is_mounted = "yes");
	INJECT_ERROR1("Z_MOUNT_TOP_NONLEG_GET_MOUNTED_NO", is_mounted = "no");
	if (strcmp(is_mounted, "no") != 0) {
		filelist_free(&flist);
		*mnted = ZFS_ALREADY;
		BAM_DPRINTF(("%s: non-legacy pool %s mounted already\n",
		    fcn, pool));
		goto mounted;
	}

	filelist_free(&flist);
	BAM_DPRINTF(("%s: non-legacy pool %s *NOT* already mounted\n",
	    fcn, pool));

	/* top dataset is not mounted. Mount it now */
	(void) snprintf(cmd, sizeof (cmd),
	    "/sbin/zfs mount %s", pool);
	ret = exec_cmd(cmd, NULL);
	INJECT_ERROR1("Z_MOUNT_TOP_NONLEG_MOUNT_CMD", ret = 1);
	if (ret != 0) {
		bam_error(_("mount of ZFS pool %s failed\n"), pool);
		return (NULL);
	}
	*mnted = ZFS_MOUNTED;
	BAM_DPRINTF(("%s: non-legacy pool %s mounted now\n", fcn, pool));
	/*FALLTHRU*/
mounted:
	/*
	 * Now get the mountpoint
	 */
	(void) snprintf(cmd, sizeof (cmd),
	    "/sbin/zfs get -Ho value mountpoint %s",
	    pool);

	ret = exec_cmd(cmd, &flist);
	INJECT_ERROR1("Z_MOUNT_TOP_NONLEG_GET_MNTPT_CMD", ret = 1);
	if (ret != 0) {
		bam_error(_("failed to determine mount point of ZFS pool %s\n"),
		    pool);
		goto error;
	}

	INJECT_ERROR1("Z_MOUNT_TOP_NONLEG_GET_MNTPT_OUT", flist.head = NULL);
	if ((flist.head == NULL) || (flist.head != flist.tail)) {
		bam_error(_("ZFS pool %s has no mount-point\n"), pool);
		goto error;
	}

	mntpt = strtok(flist.head->line, " \t\n");
	INJECT_ERROR1("Z_MOUNT_TOP_NONLEG_GET_MNTPT_STRTOK", mntpt = "foo");
	if (*mntpt != '/') {
		bam_error(_("ZFS pool %s has bad mount-point %s\n"),
		    pool, mntpt);
		goto error;
	}
	zmntpt = s_strdup(mntpt);

	filelist_free(&flist);

	BAM_DPRINTF(("%s: non-legacy pool %s is mounted at %s\n",
	    fcn, pool, zmntpt));

	return (zmntpt);

error:
	filelist_free(&flist);
	(void) umount_top_dataset(pool, *mnted, NULL);
	BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	return (NULL);
}

int
umount_top_dataset(char *pool, zfs_mnted_t mnted, char *mntpt)
{
	char		cmd[PATH_MAX];
	int		ret;
	const char	*fcn = "umount_top_dataset()";

	INJECT_ERROR1("Z_UMOUNT_TOP_INVALID_STATE", mnted = ZFS_MNT_ERROR);
	switch (mnted) {
	case LEGACY_ALREADY:
	case ZFS_ALREADY:
		/* nothing to do */
		BAM_DPRINTF(("%s: pool %s was already mounted at %s, Nothing "
		    "to umount\n", fcn, pool, mntpt ? mntpt : "NULL"));
		free(mntpt);
		return (BAM_SUCCESS);
	case LEGACY_MOUNTED:
		(void) snprintf(cmd, sizeof (cmd),
		    "/sbin/umount %s", pool);
		ret = exec_cmd(cmd, NULL);
		INJECT_ERROR1("Z_UMOUNT_TOP_LEGACY_UMOUNT_FAIL", ret = 1);
		if (ret != 0) {
			bam_error(_("umount of %s failed\n"), pool);
			free(mntpt);
			return (BAM_ERROR);
		}
		if (mntpt)
			(void) rmdir(mntpt);
		free(mntpt);
		BAM_DPRINTF(("%s: legacy pool %s was mounted by us, "
		    "successfully unmounted\n", fcn, pool));
		return (BAM_SUCCESS);
	case ZFS_MOUNTED:
		free(mntpt);
		(void) snprintf(cmd, sizeof (cmd),
		    "/sbin/zfs unmount %s", pool);
		ret = exec_cmd(cmd, NULL);
		INJECT_ERROR1("Z_UMOUNT_TOP_NONLEG_UMOUNT_FAIL", ret = 1);
		if (ret != 0) {
			bam_error(_("umount of %s failed\n"), pool);
			return (BAM_ERROR);
		}
		BAM_DPRINTF(("%s: nonleg pool %s was mounted by us, "
		    "successfully unmounted\n", fcn, pool));
		return (BAM_SUCCESS);
	default:
		bam_error(_("Internal error: bad saved mount state for "
		    "pool %s\n"), pool);
		return (BAM_ERROR);
	}
	/*NOTREACHED*/
}

/*
 * For ZFS, osdev can be one of two forms
 * It can be a "special" file as seen in mnttab: rpool/ROOT/szboot_0402
 * It can be a /dev/[r]dsk special file. We handle both instances
 */
static char *
get_pool(char *osdev)
{
	char		cmd[PATH_MAX];
	char		buf[PATH_MAX];
	filelist_t	flist = {0};
	char		*pool;
	char		*cp;
	char		*slash;
	int		ret;
	const char	*fcn = "get_pool()";

	INJECT_ERROR1("GET_POOL_OSDEV", osdev = NULL);
	if (osdev == NULL) {
		bam_error(_("NULL device: cannot determine pool name\n"));
		return (NULL);
	}

	BAM_DPRINTF(("%s: osdev arg = %s\n", fcn, osdev));

	if (osdev[0] != '/') {
		(void) strlcpy(buf, osdev, sizeof (buf));
		slash = strchr(buf, '/');
		if (slash)
			*slash = '\0';
		pool = s_strdup(buf);
		BAM_DPRINTF(("%s: got pool. pool = %s\n", fcn, pool));
		return (pool);
	} else if (strncmp(osdev, "/dev/dsk/", strlen("/dev/dsk/")) != 0 &&
	    strncmp(osdev, "/dev/rdsk/", strlen("/dev/rdsk/")) != 0) {
		bam_error(_("invalid device %s: cannot determine pool name\n"),
		    osdev);
		return (NULL);
	}

	/*
	 * Call the zfs fstyp directly since this is a zpool. This avoids
	 * potential pcfs conflicts if the first block wasn't cleared.
	 */
	(void) snprintf(cmd, sizeof (cmd),
	    "/usr/lib/fs/zfs/fstyp -a %s 2>/dev/null | /bin/grep '^name:'",
	    osdev);

	ret = exec_cmd(cmd, &flist);
	INJECT_ERROR1("GET_POOL_FSTYP", ret = 1);
	if (ret != 0) {
		bam_error(_("fstyp -a on device %s failed\n"), osdev);
		return (NULL);
	}

	INJECT_ERROR1("GET_POOL_FSTYP_OUT", flist.head = NULL);
	if ((flist.head == NULL) || (flist.head != flist.tail)) {
		bam_error(_("NULL fstyp -a output for device %s\n"), osdev);
		filelist_free(&flist);
		return (NULL);
	}

	(void) strtok(flist.head->line, "'");
	cp = strtok(NULL, "'");
	INJECT_ERROR1("GET_POOL_FSTYP_STRTOK", cp = NULL);
	if (cp == NULL) {
		bam_error(_("bad fstyp -a output for device %s\n"), osdev);
		filelist_free(&flist);
		return (NULL);
	}

	pool = s_strdup(cp);

	filelist_free(&flist);

	BAM_DPRINTF(("%s: got pool. pool = %s\n", fcn, pool));

	return (pool);
}

static char *
find_zfs_existing(char *osdev)
{
	char		*pool;
	zfs_mnted_t	mnted;
	char		*mntpt;
	char		*sign;
	const char	*fcn = "find_zfs_existing()";

	pool = get_pool(osdev);
	INJECT_ERROR1("ZFS_FIND_EXIST_POOL", pool = NULL);
	if (pool == NULL) {
		bam_error(_("failed to get pool for device: %s\n"), osdev);
		return (NULL);
	}

	mntpt = mount_top_dataset(pool, &mnted);
	INJECT_ERROR1("ZFS_FIND_EXIST_MOUNT_TOP", mntpt = NULL);
	if (mntpt == NULL) {
		bam_error(_("failed to mount top dataset for pool: %s\n"),
		    pool);
		free(pool);
		return (NULL);
	}

	sign = find_primary_common(mntpt, "zfs");
	if (sign == NULL) {
		sign = find_backup_common(mntpt, "zfs");
		BAM_DPRINTF(("%s: existing backup sign: %s\n", fcn,
		    sign ? sign : "NULL"));
	} else {
		BAM_DPRINTF(("%s: existing primary sign: %s\n", fcn, sign));
	}

	(void) umount_top_dataset(pool, mnted, mntpt);

	free(pool);

	return (sign);
}

static char *
find_existing_sign(char *osroot, char *osdev, char *fstype)
{
	const char		*fcn = "find_existing_sign()";

	INJECT_ERROR1("FIND_EXIST_NOTSUP_FS", fstype = "foofs");
	if (strcmp(fstype, "ufs") == 0) {
		BAM_DPRINTF(("%s: checking for existing UFS sign\n", fcn));
		return (find_ufs_existing(osroot));
	} else if (strcmp(fstype, "zfs") == 0) {
		BAM_DPRINTF(("%s: checking for existing ZFS sign\n", fcn));
		return (find_zfs_existing(osdev));
	} else {
		bam_error(_("boot signature not supported for fstype: %s\n"),
		    fstype);
		return (NULL);
	}
}

#define	MH_HASH_SZ	16

typedef enum {
	MH_ERROR = -1,
	MH_NOMATCH,
	MH_MATCH
} mh_search_t;

typedef struct mcache {
	char	*mc_special;
	char	*mc_mntpt;
	char	*mc_fstype;
	struct mcache *mc_next;
} mcache_t;

typedef struct mhash {
	mcache_t *mh_hash[MH_HASH_SZ];
} mhash_t;

static int
mhash_fcn(char *key)
{
	int		i;
	uint64_t	sum = 0;

	for (i = 0; key[i] != '\0'; i++) {
		sum += (uchar_t)key[i];
	}

	sum %= MH_HASH_SZ;

	assert(sum < MH_HASH_SZ);

	return (sum);
}

static mhash_t *
cache_mnttab(void)
{
	FILE		*mfp;
	struct extmnttab mnt;
	mcache_t	*mcp;
	mhash_t		*mhp;
	char		*ctds;
	int		idx;
	int		error;
	char		*special_dup;
	const char	*fcn = "cache_mnttab()";

	mfp = fopen(MNTTAB, "r");
	error = errno;
	INJECT_ERROR1("CACHE_MNTTAB_MNTTAB_ERR", mfp = NULL);
	if (mfp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"), MNTTAB,
		    strerror(error));
		return (NULL);
	}

	mhp = s_calloc(1, sizeof (mhash_t));

	resetmnttab(mfp);

	while (getextmntent(mfp, &mnt, sizeof (mnt)) == 0) {
		/* only cache ufs */
		if (strcmp(mnt.mnt_fstype, "ufs") != 0)
			continue;

		/* basename() modifies its arg, so dup it */
		special_dup = s_strdup(mnt.mnt_special);
		ctds = basename(special_dup);

		mcp = s_calloc(1, sizeof (mcache_t));
		mcp->mc_special = s_strdup(ctds);
		mcp->mc_mntpt = s_strdup(mnt.mnt_mountp);
		mcp->mc_fstype = s_strdup(mnt.mnt_fstype);
		BAM_DPRINTF(("%s: caching mount: special=%s, mntpt=%s, "
		    "fstype=%s\n", fcn, ctds, mnt.mnt_mountp, mnt.mnt_fstype));
		idx = mhash_fcn(ctds);
		mcp->mc_next = mhp->mh_hash[idx];
		mhp->mh_hash[idx] = mcp;
		free(special_dup);
	}

	(void) fclose(mfp);

	return (mhp);
}

static void
free_mnttab(mhash_t *mhp)
{
	mcache_t	*mcp;
	int		i;

	for (i = 0; i < MH_HASH_SZ; i++) {
		while ((mcp = mhp->mh_hash[i]) != NULL) {
			mhp->mh_hash[i] = mcp->mc_next;
			free(mcp->mc_special);
			free(mcp->mc_mntpt);
			free(mcp->mc_fstype);
			free(mcp);
		}
	}

	for (i = 0; i < MH_HASH_SZ; i++) {
		assert(mhp->mh_hash[i] == NULL);
	}
	free(mhp);
}

static mh_search_t
search_hash(mhash_t *mhp, char *special, char **mntpt)
{
	int		idx;
	mcache_t	*mcp;
	const char 	*fcn = "search_hash()";

	assert(mntpt);

	*mntpt = NULL;

	INJECT_ERROR1("SEARCH_HASH_FULL_PATH", special = "/foo");
	if (strchr(special, '/')) {
		bam_error(_("invalid key for mnttab hash: %s\n"), special);
		return (MH_ERROR);
	}

	idx = mhash_fcn(special);

	for (mcp = mhp->mh_hash[idx]; mcp; mcp = mcp->mc_next) {
		if (strcmp(mcp->mc_special, special) == 0)
			break;
	}

	if (mcp == NULL) {
		BAM_DPRINTF(("%s: no match in cache for: %s\n", fcn, special));
		return (MH_NOMATCH);
	}

	assert(strcmp(mcp->mc_fstype, "ufs") == 0);
	*mntpt = mcp->mc_mntpt;
	BAM_DPRINTF(("%s: *MATCH* in cache for: %s\n", fcn, special));
	return (MH_MATCH);
}

static int
check_add_ufs_sign_to_list(FILE *tfp, char *mntpt)
{
	char		*sign;
	char		*signline;
	char		signbuf[MAXNAMELEN];
	int		len;
	int		error;
	const char	*fcn = "check_add_ufs_sign_to_list()";

	/* safe to specify NULL as "osdev" arg for UFS */
	sign = find_existing_sign(mntpt, NULL, "ufs");
	if (sign == NULL) {
		/* No existing signature, nothing to add to list */
		BAM_DPRINTF(("%s: no sign on %s to add to signlist\n",
		    fcn, mntpt));
		return (0);
	}

	(void) snprintf(signbuf, sizeof (signbuf), "%s\n", sign);
	signline = signbuf;

	INJECT_ERROR1("UFS_MNTPT_SIGN_NOTUFS", signline = "pool_rpool10\n");
	if (strncmp(signline, GRUBSIGN_UFS_PREFIX,
	    strlen(GRUBSIGN_UFS_PREFIX))) {
		bam_error(_("invalid UFS boot signature %s\n"), sign);
		free(sign);
		/* ignore invalid signatures */
		return (0);
	}

	len = fputs(signline, tfp);
	error = errno;
	INJECT_ERROR1("SIGN_LIST_PUTS_ERROR", len = 0);
	if (len != strlen(signline)) {
		bam_error(_("failed to write signature %s to signature "
		    "list: %s\n"), sign, strerror(error));
		free(sign);
		return (-1);
	}

	free(sign);

	BAM_DPRINTF(("%s: successfully added sign on %s to signlist\n",
	    fcn, mntpt));
	return (0);
}

/*
 * slice is a basename not a full pathname
 */
static int
process_slice_common(char *slice, FILE *tfp, mhash_t *mhp, char *tmpmnt)
{
	int		ret;
	char		cmd[PATH_MAX];
	char		path[PATH_MAX];
	struct stat	sbuf;
	char		*mntpt;
	filelist_t	flist = {0};
	char		*fstype;
	char		blkslice[PATH_MAX];
	const char	*fcn = "process_slice_common()";


	ret = search_hash(mhp, slice, &mntpt);
	switch (ret) {
		case MH_MATCH:
			if (check_add_ufs_sign_to_list(tfp, mntpt) == -1)
				return (-1);
			else
				return (0);
		case MH_NOMATCH:
			break;
		case MH_ERROR:
		default:
			return (-1);
	}

	(void) snprintf(path, sizeof (path), "/dev/rdsk/%s", slice);
	if (stat(path, &sbuf) == -1) {
		BAM_DPRINTF(("%s: slice does not exist: %s\n", fcn, path));
		return (0);
	}

	/* Check if ufs. Call ufs fstyp directly to avoid pcfs conflicts. */
	(void) snprintf(cmd, sizeof (cmd),
	    "/usr/lib/fs/ufs/fstyp /dev/rdsk/%s 2>/dev/null",
	    slice);

	if (exec_cmd(cmd, &flist) != 0) {
		if (bam_verbose)
			bam_print(_("fstyp failed for slice: %s\n"), slice);
		return (0);
	}

	if ((flist.head == NULL) || (flist.head != flist.tail)) {
		if (bam_verbose)
			bam_print(_("bad output from fstyp for slice: %s\n"),
			    slice);
		filelist_free(&flist);
		return (0);
	}

	fstype = strtok(flist.head->line, " \t\n");
	if (fstype == NULL || strcmp(fstype, "ufs") != 0) {
		if (bam_verbose)
			bam_print(_("%s is not a ufs slice: %s\n"),
			    slice, fstype);
		filelist_free(&flist);
		return (0);
	}

	filelist_free(&flist);

	/*
	 * Since we are mounting the filesystem read-only, the
	 * the last mount field of the superblock is unchanged
	 * and does not need to be fixed up post-mount;
	 */

	(void) snprintf(blkslice, sizeof (blkslice), "/dev/dsk/%s",
	    slice);

	(void) snprintf(cmd, sizeof (cmd),
	    "/usr/sbin/mount -F ufs -o ro %s %s "
	    "> /dev/null 2>&1", blkslice, tmpmnt);

	if (exec_cmd(cmd, NULL) != 0) {
		if (bam_verbose)
			bam_print(_("mount of %s (fstype %s) failed\n"),
			    blkslice, "ufs");
		return (0);
	}

	ret = check_add_ufs_sign_to_list(tfp, tmpmnt);

	(void) snprintf(cmd, sizeof (cmd),
	    "/usr/sbin/umount -f %s > /dev/null 2>&1",
	    tmpmnt);

	if (exec_cmd(cmd, NULL) != 0) {
		bam_print(_("umount of %s failed\n"), slice);
		return (0);
	}

	return (ret);
}

static int
process_vtoc_slices(
	char *s0,
	struct vtoc *vtoc,
	FILE *tfp,
	mhash_t *mhp,
	char *tmpmnt)
{
	int		idx;
	char		slice[PATH_MAX];
	size_t		len;
	char		*cp;
	const char	*fcn = "process_vtoc_slices()";

	len = strlen(s0);

	assert(s0[len - 2] == 's' && s0[len - 1] == '0');

	s0[len - 1] = '\0';

	(void) strlcpy(slice, s0, sizeof (slice));

	s0[len - 1] = '0';

	cp = slice + len - 1;

	for (idx = 0; idx < vtoc->v_nparts; idx++) {

		(void) snprintf(cp, sizeof (slice) - (len - 1), "%u", idx);

		if (vtoc->v_part[idx].p_size == 0) {
			BAM_DPRINTF(("%s: VTOC: skipping 0-length slice: %s\n",
			    fcn, slice));
			continue;
		}

		/* Skip "SWAP", "USR", "BACKUP", "VAR", "HOME", "ALTSCTR" */
		switch (vtoc->v_part[idx].p_tag) {
		case V_SWAP:
		case V_USR:
		case V_BACKUP:
		case V_VAR:
		case V_HOME:
		case V_ALTSCTR:
			BAM_DPRINTF(("%s: VTOC: unsupported tag, "
			    "skipping: %s\n", fcn, slice));
			continue;
		default:
			BAM_DPRINTF(("%s: VTOC: supported tag, checking: %s\n",
			    fcn, slice));
			break;
		}

		/* skip unmountable and readonly slices */
		switch (vtoc->v_part[idx].p_flag) {
		case V_UNMNT:
		case V_RONLY:
			BAM_DPRINTF(("%s: VTOC: non-RDWR flag, skipping: %s\n",
			    fcn, slice));
			continue;
		default:
			BAM_DPRINTF(("%s: VTOC: RDWR flag, checking: %s\n",
			    fcn, slice));
			break;
		}

		if (process_slice_common(slice, tfp, mhp, tmpmnt) == -1) {
			return (-1);
		}
	}

	return (0);
}

static int
process_efi_slices(
	char *s0,
	struct dk_gpt *efi,
	FILE *tfp,
	mhash_t *mhp,
	char *tmpmnt)
{
	int		idx;
	char		slice[PATH_MAX];
	size_t		len;
	char		*cp;
	const char	*fcn = "process_efi_slices()";

	len = strlen(s0);

	assert(s0[len - 2] == 's' && s0[len - 1] == '0');

	s0[len - 1] = '\0';

	(void) strlcpy(slice, s0, sizeof (slice));

	s0[len - 1] = '0';

	cp = slice + len - 1;

	for (idx = 0; idx < efi->efi_nparts; idx++) {

		(void) snprintf(cp, sizeof (slice) - (len - 1), "%u", idx);

		if (efi->efi_parts[idx].p_size == 0) {
			BAM_DPRINTF(("%s: EFI: skipping 0-length slice: %s\n",
			    fcn, slice));
			continue;
		}

		/* Skip "SWAP", "USR", "BACKUP", "VAR", "HOME", "ALTSCTR" */
		switch (efi->efi_parts[idx].p_tag) {
		case V_SWAP:
		case V_USR:
		case V_BACKUP:
		case V_VAR:
		case V_HOME:
		case V_ALTSCTR:
			BAM_DPRINTF(("%s: EFI: unsupported tag, skipping: %s\n",
			    fcn, slice));
			continue;
		default:
			BAM_DPRINTF(("%s: EFI: supported tag, checking: %s\n",
			    fcn, slice));
			break;
		}

		/* skip unmountable and readonly slices */
		switch (efi->efi_parts[idx].p_flag) {
		case V_UNMNT:
		case V_RONLY:
			BAM_DPRINTF(("%s: EFI: non-RDWR flag, skipping: %s\n",
			    fcn, slice));
			continue;
		default:
			BAM_DPRINTF(("%s: EFI: RDWR flag, checking: %s\n",
			    fcn, slice));
			break;
		}

		if (process_slice_common(slice, tfp, mhp, tmpmnt) == -1) {
			return (-1);
		}
	}

	return (0);
}

/*
 * s0 is a basename not a full path
 */
static int
process_slice0(char *s0, FILE *tfp, mhash_t *mhp, char *tmpmnt)
{
	struct vtoc		vtoc;
	struct dk_gpt		*efi;
	char			s0path[PATH_MAX];
	struct stat		sbuf;
	int			e_flag;
	int			v_flag;
	int			retval;
	int			err;
	int			fd;
	const char		*fcn = "process_slice0()";

	(void) snprintf(s0path, sizeof (s0path), "/dev/rdsk/%s", s0);

	if (stat(s0path, &sbuf) == -1) {
		BAM_DPRINTF(("%s: slice 0 does not exist: %s\n", fcn, s0path));
		return (0);
	}

	fd = open(s0path, O_NONBLOCK|O_RDONLY);
	if (fd == -1) {
		bam_error(_("failed to open file: %s: %s\n"), s0path,
		    strerror(errno));
		return (0);
	}

	e_flag = v_flag = 0;
	retval = ((err = read_vtoc(fd, &vtoc)) >= 0) ? 0 : err;
	switch (retval) {
		case VT_EIO:
			BAM_DPRINTF(("%s: VTOC: failed to read: %s\n",
			    fcn, s0path));
			break;
		case VT_EINVAL:
			BAM_DPRINTF(("%s: VTOC: is INVALID: %s\n",
			    fcn, s0path));
			break;
		case VT_ERROR:
			BAM_DPRINTF(("%s: VTOC: unknown error while "
			    "reading: %s\n", fcn, s0path));
			break;
		case VT_ENOTSUP:
			e_flag = 1;
			BAM_DPRINTF(("%s: VTOC: not supported: %s\n",
			    fcn, s0path));
			break;
		case 0:
			v_flag = 1;
			BAM_DPRINTF(("%s: VTOC: SUCCESS reading: %s\n",
			    fcn, s0path));
			break;
		default:
			BAM_DPRINTF(("%s: VTOC: READ: unknown return "
			    "code: %s\n", fcn, s0path));
			break;
	}


	if (e_flag) {
		e_flag = 0;
		retval = ((err = efi_alloc_and_read(fd, &efi)) >= 0) ? 0 : err;
		switch (retval) {
		case VT_EIO:
			BAM_DPRINTF(("%s: EFI: failed to read: %s\n",
			    fcn, s0path));
			break;
		case VT_EINVAL:
			BAM_DPRINTF(("%s: EFI: is INVALID: %s\n", fcn, s0path));
			break;
		case VT_ERROR:
			BAM_DPRINTF(("%s: EFI: unknown error while "
			    "reading: %s\n", fcn, s0path));
			break;
		case VT_ENOTSUP:
			BAM_DPRINTF(("%s: EFI: not supported: %s\n",
			    fcn, s0path));
			break;
		case 0:
			e_flag = 1;
			BAM_DPRINTF(("%s: EFI: SUCCESS reading: %s\n",
			    fcn, s0path));
			break;
		default:
			BAM_DPRINTF(("%s: EFI: READ: unknown return code: %s\n",
			    fcn, s0path));
			break;
		}
	}

	(void) close(fd);

	if (v_flag) {
		retval = process_vtoc_slices(s0,
		    &vtoc, tfp, mhp, tmpmnt);
	} else if (e_flag) {
		retval = process_efi_slices(s0,
		    efi, tfp, mhp, tmpmnt);
	} else {
		BAM_DPRINTF(("%s: disk has neither VTOC nor EFI: %s\n",
		    fcn, s0path));
		return (0);
	}

	return (retval);
}

/*
 * Find and create a list of all existing UFS boot signatures
 */
static int
FindAllUfsSignatures(void)
{
	mhash_t		*mnttab_hash;
	DIR		*dirp = NULL;
	struct dirent	*dp;
	char		tmpmnt[PATH_MAX];
	char		cmd[PATH_MAX];
	struct stat	sb;
	int		fd;
	FILE		*tfp;
	size_t		len;
	int		ret;
	int		error;
	const char	*fcn = "FindAllUfsSignatures()";

	if (stat(UFS_SIGNATURE_LIST, &sb) != -1)  {
		bam_print(_("       - signature list %s exists\n"),
		    UFS_SIGNATURE_LIST);
		return (0);
	}

	fd = open(UFS_SIGNATURE_LIST".tmp",
	    O_RDWR|O_CREAT|O_TRUNC, 0644);
	error = errno;
	INJECT_ERROR1("SIGN_LIST_TMP_TRUNC", fd = -1);
	if (fd == -1) {
		bam_error(_("failed to open file: %s: %s\n"),
		    UFS_SIGNATURE_LIST".tmp", strerror(error));
		return (-1);
	}

	ret = close(fd);
	error = errno;
	INJECT_ERROR1("SIGN_LIST_TMP_CLOSE", ret = -1);
	if (ret == -1) {
		bam_error(_("failed to close file: %s: %s\n"),
		    UFS_SIGNATURE_LIST".tmp", strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (-1);
	}

	tfp = fopen(UFS_SIGNATURE_LIST".tmp", "a");
	error = errno;
	INJECT_ERROR1("SIGN_LIST_APPEND_FOPEN", tfp = NULL);
	if (tfp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"),
		    UFS_SIGNATURE_LIST".tmp", strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (-1);
	}

	mnttab_hash = cache_mnttab();
	INJECT_ERROR1("CACHE_MNTTAB_ERROR", mnttab_hash = NULL);
	if (mnttab_hash == NULL) {
		(void) fclose(tfp);
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		bam_error(_("%s: failed to cache /etc/mnttab\n"), fcn);
		return (-1);
	}

	(void) snprintf(tmpmnt, sizeof (tmpmnt),
	    "/tmp/bootadm_ufs_sign_mnt.%d", getpid());
	(void) unlink(tmpmnt);

	ret = mkdirp(tmpmnt, DIR_PERMS);
	error = errno;
	INJECT_ERROR1("MKDIRP_SIGN_MNT", ret = -1);
	if (ret == -1) {
		bam_error(_("mkdir of %s failed: %s\n"), tmpmnt,
		    strerror(error));
		free_mnttab(mnttab_hash);
		(void) fclose(tfp);
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (-1);
	}

	dirp = opendir("/dev/rdsk");
	error = errno;
	INJECT_ERROR1("OPENDIR_DEV_RDSK", dirp = NULL);
	if (dirp == NULL) {
		bam_error(_("opendir of %s failed: %s\n"), "/dev/rdsk",
		    strerror(error));
		goto fail;
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		/*
		 * we only look for the s0 slice. This is guranteed to
		 * have 's' at len - 2.
		 */
		len = strlen(dp->d_name);
		if (dp->d_name[len - 2 ] != 's' || dp->d_name[len - 1] != '0') {
			BAM_DPRINTF(("%s: skipping non-s0 slice: %s\n",
			    fcn, dp->d_name));
			continue;
		}

		ret = process_slice0(dp->d_name, tfp, mnttab_hash, tmpmnt);
		INJECT_ERROR1("PROCESS_S0_FAIL", ret = -1);
		if (ret == -1)
			goto fail;
	}

	(void) closedir(dirp);
	free_mnttab(mnttab_hash);
	(void) rmdir(tmpmnt);

	ret = fclose(tfp);
	error = errno;
	INJECT_ERROR1("FCLOSE_SIGNLIST_TMP", ret = EOF);
	if (ret == EOF) {
		bam_error(_("failed to close file: %s: %s\n"),
		    UFS_SIGNATURE_LIST".tmp", strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (-1);
	}

	/* We have a list of existing GRUB signatures. Sort it first */
	(void) snprintf(cmd, sizeof (cmd),
	    "/usr/bin/sort -u %s.tmp > %s.sorted",
	    UFS_SIGNATURE_LIST, UFS_SIGNATURE_LIST);

	ret = exec_cmd(cmd, NULL);
	INJECT_ERROR1("SORT_SIGN_LIST", ret = 1);
	if (ret != 0) {
		bam_error(_("error sorting GRUB UFS boot signatures\n"));
		(void) unlink(UFS_SIGNATURE_LIST".sorted");
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (-1);
	}

	(void) unlink(UFS_SIGNATURE_LIST".tmp");

	ret = rename(UFS_SIGNATURE_LIST".sorted", UFS_SIGNATURE_LIST);
	error = errno;
	INJECT_ERROR1("RENAME_TMP_SIGNLIST", ret = -1);
	if (ret == -1) {
		bam_error(_("rename to file failed: %s: %s\n"),
		    UFS_SIGNATURE_LIST, strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST".sorted");
		return (-1);
	}

	if (stat(UFS_SIGNATURE_LIST, &sb) == 0 && sb.st_size == 0) {
		BAM_DPRINTF(("%s: generated zero length signlist: %s.\n",
		    fcn, UFS_SIGNATURE_LIST));
	}

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	return (0);

fail:
	if (dirp)
		(void) closedir(dirp);
	free_mnttab(mnttab_hash);
	(void) rmdir(tmpmnt);
	(void) fclose(tfp);
	(void) unlink(UFS_SIGNATURE_LIST".tmp");
	BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	return (-1);
}

static char *
create_ufs_sign(void)
{
	struct stat	sb;
	int		signnum = -1;
	char		tmpsign[MAXNAMELEN + 1];
	char		*numstr;
	int		i;
	FILE		*tfp;
	int		ret;
	int		error;
	const char	*fcn = "create_ufs_sign()";

	bam_print(_("  - searching for UFS boot signatures\n"));

	ret = FindAllUfsSignatures();
	INJECT_ERROR1("FIND_ALL_UFS", ret = -1);
	if (ret == -1) {
		bam_error(_("search for UFS boot signatures failed\n"));
		return (NULL);
	}

	/* Make sure the list exists and is owned by root */
	INJECT_ERROR1("SIGNLIST_NOT_CREATED",
	    (void) unlink(UFS_SIGNATURE_LIST));
	if (stat(UFS_SIGNATURE_LIST, &sb) == -1 || sb.st_uid != 0) {
		(void) unlink(UFS_SIGNATURE_LIST);
		bam_error(_("missing UFS signature list file: %s\n"),
		    UFS_SIGNATURE_LIST);
		return (NULL);
	}

	if (sb.st_size == 0) {
		bam_print(_("   - no existing UFS boot signatures\n"));
		i = 0;
		goto found;
	}

	/* The signature list was sorted when it was created */
	tfp = fopen(UFS_SIGNATURE_LIST, "r");
	error = errno;
	INJECT_ERROR1("FOPEN_SIGN_LIST", tfp = NULL);
	if (tfp == NULL) {
		bam_error(_("error opening UFS boot signature list "
		    "file %s: %s\n"), UFS_SIGNATURE_LIST, strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST);
		return (NULL);
	}

	for (i = 0; s_fgets(tmpsign, sizeof (tmpsign), tfp); i++) {

		if (strncmp(tmpsign, GRUBSIGN_UFS_PREFIX,
		    strlen(GRUBSIGN_UFS_PREFIX)) != 0) {
			(void) fclose(tfp);
			(void) unlink(UFS_SIGNATURE_LIST);
			bam_error(_("bad UFS boot signature: %s\n"), tmpsign);
			return (NULL);
		}
		numstr = tmpsign + strlen(GRUBSIGN_UFS_PREFIX);

		if (numstr[0] == '\0' || !isdigit(numstr[0])) {
			(void) fclose(tfp);
			(void) unlink(UFS_SIGNATURE_LIST);
			bam_error(_("bad UFS boot signature: %s\n"), tmpsign);
			return (NULL);
		}

		signnum = atoi(numstr);
		INJECT_ERROR1("NEGATIVE_SIGN", signnum = -1);
		if (signnum < 0) {
			(void) fclose(tfp);
			(void) unlink(UFS_SIGNATURE_LIST);
			bam_error(_("bad UFS boot signature: %s\n"), tmpsign);
			return (NULL);
		}

		if (i != signnum) {
			BAM_DPRINTF(("%s: found hole %d in sign list.\n",
			    fcn, i));
			break;
		}
	}

	(void) fclose(tfp);

found:
	(void) snprintf(tmpsign, sizeof (tmpsign), "rootfs%d", i);

	/* add the ufs signature to the /var/run list of signatures */
	ret = ufs_add_to_sign_list(tmpsign);
	INJECT_ERROR1("UFS_ADD_TO_SIGN_LIST", ret = -1);
	if (ret == -1) {
		(void) unlink(UFS_SIGNATURE_LIST);
		bam_error(_("failed to add sign %s to signlist.\n"), tmpsign);
		return (NULL);
	}

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));

	return (s_strdup(tmpsign));
}

static char *
get_fstype(char *osroot)
{
	FILE		*mntfp;
	struct mnttab	mp = {0};
	struct mnttab	mpref = {0};
	int		error;
	int		ret;
	const char	*fcn = "get_fstype()";

	INJECT_ERROR1("GET_FSTYPE_OSROOT", osroot = NULL);
	if (osroot == NULL) {
		bam_error(_("no OS mountpoint. Cannot determine fstype\n"));
		return (NULL);
	}

	mntfp = fopen(MNTTAB, "r");
	error = errno;
	INJECT_ERROR1("GET_FSTYPE_FOPEN", mntfp = NULL);
	if (mntfp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"), MNTTAB,
		    strerror(error));
		return (NULL);
	}

	if (*osroot == '\0')
		mpref.mnt_mountp = "/";
	else
		mpref.mnt_mountp = osroot;

	ret = getmntany(mntfp, &mp, &mpref);
	INJECT_ERROR1("GET_FSTYPE_GETMNTANY", ret = 1);
	if (ret != 0) {
		bam_error(_("failed to find OS mountpoint %s in %s\n"),
		    osroot, MNTTAB);
		(void) fclose(mntfp);
		return (NULL);
	}
	(void) fclose(mntfp);

	INJECT_ERROR1("GET_FSTYPE_NULL", mp.mnt_fstype = NULL);
	if (mp.mnt_fstype == NULL) {
		bam_error(_("NULL fstype found for OS root %s\n"), osroot);
		return (NULL);
	}

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));

	return (s_strdup(mp.mnt_fstype));
}

static char *
create_zfs_sign(char *osdev)
{
	char		tmpsign[PATH_MAX];
	char		*pool;
	const char	*fcn = "create_zfs_sign()";

	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, osdev));

	/*
	 * First find the pool name
	 */
	pool = get_pool(osdev);
	INJECT_ERROR1("CREATE_ZFS_SIGN_GET_POOL", pool = NULL);
	if (pool == NULL) {
		bam_error(_("failed to get pool name from %s\n"), osdev);
		return (NULL);
	}

	(void) snprintf(tmpsign, sizeof (tmpsign), "pool_%s", pool);

	BAM_DPRINTF(("%s: created ZFS sign: %s\n", fcn, tmpsign));

	free(pool);

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));

	return (s_strdup(tmpsign));
}

static char *
create_new_sign(char *osdev, char *fstype)
{
	char		*sign;
	const char	*fcn = "create_new_sign()";

	INJECT_ERROR1("NEW_SIGN_FSTYPE", fstype = "foofs");

	if (strcmp(fstype, "zfs") == 0) {
		BAM_DPRINTF(("%s: created new ZFS sign\n", fcn));
		sign = create_zfs_sign(osdev);
	} else if (strcmp(fstype, "ufs") == 0) {
		BAM_DPRINTF(("%s: created new UFS sign\n", fcn));
		sign = create_ufs_sign();
	} else {
		bam_error(_("boot signature not supported for fstype: %s\n"),
		    fstype);
		sign = NULL;
	}

	BAM_DPRINTF(("%s: created new sign: %s\n", fcn,
	    sign ? sign : "<NULL>"));
	return (sign);
}

static int
set_backup_common(char *mntpt, char *sign)
{
	FILE		*bfp;
	char		backup[PATH_MAX];
	char		tmpsign[PATH_MAX];
	int		error;
	char		*bdir;
	char		*backup_dup;
	struct stat	sb;
	int		ret;
	const char	*fcn = "set_backup_common()";

	(void) snprintf(backup, sizeof (backup), "%s%s",
	    mntpt, GRUBSIGN_BACKUP);

	/* First read the backup */
	bfp = fopen(backup, "r");
	if (bfp != NULL) {
		while (s_fgets(tmpsign, sizeof (tmpsign), bfp)) {
			if (strcmp(tmpsign, sign) == 0) {
				BAM_DPRINTF(("%s: found sign (%s) in backup.\n",
				    fcn, sign));
				(void) fclose(bfp);
				return (0);
			}
		}
		(void) fclose(bfp);
		BAM_DPRINTF(("%s: backup exists but sign %s not found\n",
		    fcn, sign));
	} else {
		BAM_DPRINTF(("%s: no backup file (%s) found.\n", fcn, backup));
	}

	/*
	 * Didn't find the correct signature. First create
	 * the directory if necessary.
	 */

	/* dirname() modifies its argument so dup it */
	backup_dup = s_strdup(backup);
	bdir = dirname(backup_dup);
	assert(bdir);

	ret = stat(bdir, &sb);
	INJECT_ERROR1("SET_BACKUP_STAT", ret = -1);
	if (ret == -1) {
		BAM_DPRINTF(("%s: backup dir (%s) does not exist.\n",
		    fcn, bdir));
		ret = mkdirp(bdir, DIR_PERMS);
		error = errno;
		INJECT_ERROR1("SET_BACKUP_MKDIRP", ret = -1);
		if (ret == -1) {
			bam_error(_("mkdirp() of backup dir failed: %s: %s\n"),
			    GRUBSIGN_BACKUP, strerror(error));
			free(backup_dup);
			return (-1);
		}
	}
	free(backup_dup);

	/*
	 * Open the backup in append mode to add the correct
	 * signature;
	 */
	bfp = fopen(backup, "a");
	error = errno;
	INJECT_ERROR1("SET_BACKUP_FOPEN_A", bfp = NULL);
	if (bfp == NULL) {
		bam_error(_("error opening boot signature backup "
		    "file %s: %s\n"), GRUBSIGN_BACKUP, strerror(error));
		return (-1);
	}

	(void) snprintf(tmpsign, sizeof (tmpsign), "%s\n", sign);

	ret = fputs(tmpsign, bfp);
	error = errno;
	INJECT_ERROR1("SET_BACKUP_FPUTS", ret = 0);
	if (ret != strlen(tmpsign)) {
		bam_error(_("error writing boot signature backup "
		    "file %s: %s\n"), GRUBSIGN_BACKUP, strerror(error));
		(void) fclose(bfp);
		return (-1);
	}

	(void) fclose(bfp);

	if (bam_verbose)
		bam_print(_("updated boot signature backup file %s\n"),
		    GRUBSIGN_BACKUP);

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));

	return (0);
}

static int
set_backup_ufs(char *osroot, char *sign)
{
	const char	*fcn = "set_backup_ufs()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osroot, sign));
	return (set_backup_common(osroot, sign));
}

static int
set_backup_zfs(char *osdev, char *sign)
{
	char		*pool;
	char		*mntpt;
	zfs_mnted_t	mnted;
	int		ret;
	const char	*fcn = "set_backup_zfs()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osdev, sign));

	pool = get_pool(osdev);
	INJECT_ERROR1("SET_BACKUP_GET_POOL", pool = NULL);
	if (pool == NULL) {
		bam_error(_("failed to get pool name from %s\n"), osdev);
		return (-1);
	}

	mntpt = mount_top_dataset(pool, &mnted);
	INJECT_ERROR1("SET_BACKUP_MOUNT_DATASET", mntpt = NULL);
	if (mntpt == NULL) {
		bam_error(_("failed to mount top dataset for %s\n"), pool);
		free(pool);
		return (-1);
	}

	ret = set_backup_common(mntpt, sign);

	(void) umount_top_dataset(pool, mnted, mntpt);

	free(pool);

	INJECT_ERROR1("SET_BACKUP_ZFS_FAIL", ret = 1);
	if (ret == 0) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}

	return (ret);
}

static int
set_backup(char *osroot, char *osdev, char *sign, char *fstype)
{
	const char	*fcn = "set_backup()";
	int		ret;

	INJECT_ERROR1("SET_BACKUP_FSTYPE", fstype = "foofs");

	if (strcmp(fstype, "ufs") == 0) {
		BAM_DPRINTF(("%s: setting UFS backup sign\n", fcn));
		ret = set_backup_ufs(osroot, sign);
	} else if (strcmp(fstype, "zfs") == 0) {
		BAM_DPRINTF(("%s: setting ZFS backup sign\n", fcn));
		ret = set_backup_zfs(osdev, sign);
	} else {
		bam_error(_("boot signature not supported for fstype: %s\n"),
		    fstype);
		ret = -1;
	}

	if (ret == 0) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}

	return (ret);
}

static int
set_primary_common(char *mntpt, char *sign)
{
	char		signfile[PATH_MAX];
	char		signdir[PATH_MAX];
	struct stat	sb;
	int		fd;
	int		error;
	int		ret;
	const char	*fcn = "set_primary_common()";

	(void) snprintf(signfile, sizeof (signfile), "%s/%s/%s",
	    mntpt, GRUBSIGN_DIR, sign);

	if (stat(signfile, &sb) != -1) {
		if (bam_verbose)
			bam_print(_("primary sign %s exists\n"), sign);
		return (0);
	} else {
		BAM_DPRINTF(("%s: primary sign (%s) does not exist\n",
		    fcn, signfile));
	}

	(void) snprintf(signdir, sizeof (signdir), "%s/%s",
	    mntpt, GRUBSIGN_DIR);

	if (stat(signdir, &sb) == -1) {
		BAM_DPRINTF(("%s: primary signdir (%s) does not exist\n",
		    fcn, signdir));
		ret = mkdirp(signdir, DIR_PERMS);
		error = errno;
		INJECT_ERROR1("SET_PRIMARY_MKDIRP", ret = -1);
		if (ret == -1) {
			bam_error(_("error creating boot signature "
			    "directory %s: %s\n"), signdir, strerror(errno));
			return (-1);
		}
	}

	fd = open(signfile, O_RDWR|O_CREAT|O_TRUNC, 0444);
	error = errno;
	INJECT_ERROR1("PRIMARY_SIGN_CREAT", fd = -1);
	if (fd == -1) {
		bam_error(_("error creating primary boot signature %s: %s\n"),
		    signfile, strerror(error));
		return (-1);
	}

	ret = fsync(fd);
	error = errno;
	INJECT_ERROR1("PRIMARY_FSYNC", ret = -1);
	if (ret != 0) {
		bam_error(_("error syncing primary boot signature %s: %s\n"),
		    signfile, strerror(error));
	}

	(void) close(fd);

	if (bam_verbose)
		bam_print(_("created primary GRUB boot signature: %s\n"),
		    signfile);

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));

	return (0);
}

static int
set_primary_ufs(char *osroot, char *sign)
{
	const char	*fcn = "set_primary_ufs()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osroot, sign));
	return (set_primary_common(osroot, sign));
}

static int
set_primary_zfs(char *osdev, char *sign)
{
	char		*pool;
	char		*mntpt;
	zfs_mnted_t	mnted;
	int		ret;
	const char	*fcn = "set_primary_zfs()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osdev, sign));

	pool = get_pool(osdev);
	INJECT_ERROR1("SET_PRIMARY_ZFS_GET_POOL", pool = NULL);
	if (pool == NULL) {
		bam_error(_("failed to get pool name from %s\n"), osdev);
		return (-1);
	}

	/* Pool name must exist in the sign */
	ret = (strstr(sign, pool) != NULL);
	INJECT_ERROR1("SET_PRIMARY_ZFS_POOL_SIGN_INCOMPAT", ret = 0);
	if (ret == 0) {
		bam_error(_("pool name %s not present in signature %s\n"),
		    pool, sign);
		free(pool);
		return (-1);
	}

	mntpt = mount_top_dataset(pool, &mnted);
	INJECT_ERROR1("SET_PRIMARY_ZFS_MOUNT_DATASET", mntpt = NULL);
	if (mntpt == NULL) {
		bam_error(_("failed to mount top dataset for %s\n"), pool);
		free(pool);
		return (-1);
	}

	ret = set_primary_common(mntpt, sign);

	(void) umount_top_dataset(pool, mnted, mntpt);

	free(pool);

	INJECT_ERROR1("SET_PRIMARY_ZFS_FAIL", ret = 1);
	if (ret == 0) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}

	return (ret);
}

static int
set_primary(char *osroot, char *osdev, char *sign, char *fstype)
{
	const char	*fcn = "set_primary()";
	int		ret;

	INJECT_ERROR1("SET_PRIMARY_FSTYPE", fstype = "foofs");
	if (strcmp(fstype, "ufs") == 0) {
		BAM_DPRINTF(("%s: setting UFS primary sign\n", fcn));
		ret = set_primary_ufs(osroot, sign);
	} else if (strcmp(fstype, "zfs") == 0) {
		BAM_DPRINTF(("%s: setting ZFS primary sign\n", fcn));
		ret = set_primary_zfs(osdev, sign);
	} else {
		bam_error(_("boot signature not supported for fstype: %s\n"),
		    fstype);
		ret = -1;
	}

	if (ret == 0) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}

	return (ret);
}

static int
ufs_add_to_sign_list(char *sign)
{
	FILE		*tfp;
	char		signline[MAXNAMELEN];
	char		cmd[PATH_MAX];
	int		ret;
	int		error;
	const char	*fcn = "ufs_add_to_sign_list()";

	INJECT_ERROR1("ADD_TO_SIGN_LIST_NOT_UFS", sign = "pool_rpool5");
	if (strncmp(sign, GRUBSIGN_UFS_PREFIX,
	    strlen(GRUBSIGN_UFS_PREFIX)) != 0) {
		bam_error(_("invalid UFS boot signature %s\n"), sign);
		(void) unlink(UFS_SIGNATURE_LIST);
		return (-1);
	}

	/*
	 * most failures in this routine are not a fatal error
	 * We simply unlink the /var/run file and continue
	 */

	ret = rename(UFS_SIGNATURE_LIST, UFS_SIGNATURE_LIST".tmp");
	error = errno;
	INJECT_ERROR1("ADD_TO_SIGN_LIST_RENAME", ret = -1);
	if (ret == -1) {
		bam_error(_("rename to file failed: %s: %s\n"),
		    UFS_SIGNATURE_LIST".tmp", strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST);
		return (0);
	}

	tfp = fopen(UFS_SIGNATURE_LIST".tmp", "a");
	error = errno;
	INJECT_ERROR1("ADD_TO_SIGN_LIST_FOPEN", tfp = NULL);
	if (tfp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"),
		    UFS_SIGNATURE_LIST".tmp", strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (0);
	}

	(void) snprintf(signline, sizeof (signline), "%s\n", sign);

	ret = fputs(signline, tfp);
	error = errno;
	INJECT_ERROR1("ADD_TO_SIGN_LIST_FPUTS", ret = 0);
	if (ret != strlen(signline)) {
		bam_error(_("failed to write signature %s to signature "
		    "list: %s\n"), sign, strerror(error));
		(void) fclose(tfp);
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (0);
	}

	ret = fclose(tfp);
	error = errno;
	INJECT_ERROR1("ADD_TO_SIGN_LIST_FCLOSE", ret = EOF);
	if (ret == EOF) {
		bam_error(_("failed to close file: %s: %s\n"),
		    UFS_SIGNATURE_LIST".tmp", strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (0);
	}

	/* Sort the list again */
	(void) snprintf(cmd, sizeof (cmd),
	    "/usr/bin/sort -u %s.tmp > %s.sorted",
	    UFS_SIGNATURE_LIST, UFS_SIGNATURE_LIST);

	ret = exec_cmd(cmd, NULL);
	INJECT_ERROR1("ADD_TO_SIGN_LIST_SORT", ret = 1);
	if (ret != 0) {
		bam_error(_("error sorting GRUB UFS boot signatures\n"));
		(void) unlink(UFS_SIGNATURE_LIST".sorted");
		(void) unlink(UFS_SIGNATURE_LIST".tmp");
		return (0);
	}

	(void) unlink(UFS_SIGNATURE_LIST".tmp");

	ret = rename(UFS_SIGNATURE_LIST".sorted", UFS_SIGNATURE_LIST);
	error = errno;
	INJECT_ERROR1("ADD_TO_SIGN_LIST_RENAME2", ret = -1);
	if (ret == -1) {
		bam_error(_("rename to file failed: %s: %s\n"),
		    UFS_SIGNATURE_LIST, strerror(error));
		(void) unlink(UFS_SIGNATURE_LIST".sorted");
		return (0);
	}

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));

	return (0);
}

static int
set_signature(char *osroot, char *osdev, char *sign, char *fstype)
{
	int		ret;
	const char	*fcn = "set_signature()";

	BAM_DPRINTF(("%s: entered. args: %s %s %s %s\n", fcn,
	    osroot, osdev, sign, fstype));

	ret = set_backup(osroot, osdev, sign, fstype);
	INJECT_ERROR1("SET_SIGNATURE_BACKUP", ret = -1);
	if (ret == -1) {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
		bam_error(_("failed to set backup sign (%s) for %s: %s\n"),
		    sign, osroot, osdev);
		return (-1);
	}

	ret = set_primary(osroot, osdev, sign, fstype);
	INJECT_ERROR1("SET_SIGNATURE_PRIMARY", ret = -1);

	if (ret == 0) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
		bam_error(_("failed to set primary sign (%s) for %s: %s\n"),
		    sign, osroot, osdev);

	}
	return (ret);
}

char *
get_grubsign(char *osroot, char *osdev)
{
	char		*grubsign;	/* (<sign>,#,#) */
	char		*slice;
	int		fdiskpart;
	char		*sign;
	char		*fstype;
	int		ret;
	const char	*fcn = "get_grubsign()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osroot, osdev));
	fstype = get_fstype(osroot);
	INJECT_ERROR1("GET_GRUBSIGN_FSTYPE", fstype = NULL);
	if (fstype == NULL) {
		bam_error(_("failed to get fstype for %s\n"), osroot);
		return (NULL);
	}

	sign = find_existing_sign(osroot, osdev, fstype);
	INJECT_ERROR1("FIND_EXISTING_SIGN", sign = NULL);
	if (sign == NULL) {
		BAM_DPRINTF(("%s: no existing grubsign for %s: %s\n",
		    fcn, osroot, osdev));
		sign = create_new_sign(osdev, fstype);
		INJECT_ERROR1("CREATE_NEW_SIGN", sign = NULL);
		if (sign == NULL) {
			bam_error(_("failed to create GRUB boot signature for "
			    "device: %s\n"), osdev);
			free(fstype);
			return (NULL);
		}
	}

	ret = set_signature(osroot, osdev, sign, fstype);
	INJECT_ERROR1("SET_SIGNATURE_FAIL", ret = -1);
	if (ret == -1) {
		bam_error(_("failed to write GRUB boot signature for "
		    "device: %s\n"), osdev);
		free(sign);
		free(fstype);
		(void) unlink(UFS_SIGNATURE_LIST);
		return (NULL);
	}

	free(fstype);

	if (bam_verbose)
		bam_print(_("found or created GRUB signature %s for %s\n"),
		    sign, osdev);

	fdiskpart = get_partition(osdev);
	INJECT_ERROR1("GET_GRUBSIGN_FDISK", fdiskpart = PARTNO_NOTFOUND);
	if (fdiskpart == PARTNO_NOTFOUND) {
		bam_error(_("failed to determine fdisk partition: %s\n"),
		    osdev);
		free(sign);
		return (NULL);
	}

	slice = strrchr(osdev, 's');

	if (fdiskpart == PARTNO_EFI) {
		fdiskpart = atoi(&slice[1]);
		slice = NULL;
	}

	grubsign = s_calloc(1, MAXNAMELEN + 10);
	if (slice) {
		(void) snprintf(grubsign, MAXNAMELEN + 10, "(%s,%d,%c)",
		    sign, fdiskpart, slice[1] + 'a' - '0');
	} else
		(void) snprintf(grubsign, MAXNAMELEN + 10, "(%s,%d)",
		    sign, fdiskpart);

	free(sign);

	BAM_DPRINTF(("%s: successfully created grubsign %s\n", fcn, grubsign));

	return (grubsign);
}

static char *
get_title(char *rootdir)
{
	static char	title[80];
	char		*cp = NULL;
	char		release[PATH_MAX];
	FILE		*fp;
	const char	*fcn = "get_title()";

	/* open the /etc/release file */
	(void) snprintf(release, sizeof (release), "%s/etc/release", rootdir);

	fp = fopen(release, "r");
	if (fp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"), release,
		    strerror(errno));
		cp = NULL;
		goto out;
	}

	/* grab first line of /etc/release */
	cp = s_fgets(title, sizeof (title), fp);
	if (cp) {
		while (isspace(*cp))    /* remove leading spaces */
			cp++;
	}

	(void) fclose(fp);

out:
	cp = cp ? cp : "Oracle Solaris";

	BAM_DPRINTF(("%s: got title: %s\n", fcn, cp));

	return (cp);
}

char *
get_special(char *mountp)
{
	FILE		*mntfp;
	struct mnttab	mp = {0};
	struct mnttab	mpref = {0};
	int		error;
	int		ret;
	const char 	*fcn = "get_special()";

	INJECT_ERROR1("GET_SPECIAL_MNTPT", mountp = NULL);
	if (mountp == NULL) {
		bam_error(_("cannot get special file: NULL mount-point\n"));
		return (NULL);
	}

	mntfp = fopen(MNTTAB, "r");
	error = errno;
	INJECT_ERROR1("GET_SPECIAL_MNTTAB_OPEN", mntfp = NULL);
	if (mntfp == NULL) {
		bam_error(_("failed to open file: %s: %s\n"), MNTTAB,
		    strerror(error));
		return (NULL);
	}

	if (*mountp == '\0')
		mpref.mnt_mountp = "/";
	else
		mpref.mnt_mountp = mountp;

	ret = getmntany(mntfp, &mp, &mpref);
	INJECT_ERROR1("GET_SPECIAL_MNTTAB_SEARCH", ret = 1);
	if (ret != 0) {
		(void) fclose(mntfp);
		BAM_DPRINTF(("%s: Cannot get special file:  mount-point %s "
		    "not in mnttab\n", fcn, mountp));
		return (NULL);
	}
	(void) fclose(mntfp);

	BAM_DPRINTF(("%s: returning special: %s\n", fcn, mp.mnt_special));

	return (s_strdup(mp.mnt_special));
}

static void
free_physarray(char **physarray, int n)
{
	int			i;
	const char		*fcn = "free_physarray()";

	assert(physarray);
	assert(n);

	BAM_DPRINTF(("%s: entering args: %d\n", fcn, n));

	for (i = 0; i < n; i++) {
		free(physarray[i]);
	}
	free(physarray);

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
}

static int
zfs_get_physical(char *special, char ***physarray, int *n)
{
	char			sdup[PATH_MAX];
	char			cmd[PATH_MAX];
	char			dsk[PATH_MAX];
	char			*pool;
	filelist_t		flist = {0};
	line_t			*lp;
	line_t			*startlp;
	char			*comp1;
	int			i;
	int			ret;
	const char		*fcn = "zfs_get_physical()";

	assert(special);

	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, special));

	INJECT_ERROR1("INVALID_ZFS_SPECIAL", special = "/foo");
	if (special[0] == '/') {
		bam_error(_("invalid device for ZFS filesystem: %s\n"),
		    special);
		return (-1);
	}

	(void) strlcpy(sdup, special, sizeof (sdup));

	pool = strtok(sdup, "/");
	INJECT_ERROR1("ZFS_GET_PHYS_POOL", pool = NULL);
	if (pool == NULL) {
		bam_error(_("cannot derive ZFS pool from special: %s\n"),
		    special);
		return (-1);
	}

	(void) snprintf(cmd, sizeof (cmd), "/sbin/zpool status %s", pool);

	ret = exec_cmd(cmd, &flist);
	INJECT_ERROR1("ZFS_GET_PHYS_STATUS", ret = 1);
	if (ret != 0) {
		bam_error(_("cannot get zpool status for pool: %s\n"), pool);
		return (-1);
	}

	INJECT_ERROR1("ZFS_GET_PHYS_STATUS_OUT", flist.head = NULL);
	if (flist.head == NULL) {
		bam_error(_("bad zpool status for pool=%s\n"), pool);
		filelist_free(&flist);
		return (-1);
	}

	for (lp = flist.head; lp; lp = lp->next) {
		BAM_DPRINTF(("%s: strtok() zpool status line=%s\n",
		    fcn, lp->line));
		comp1 = strtok(lp->line, " \t");
		if (comp1 == NULL) {
			free(lp->line);
			lp->line = NULL;
		} else {
			comp1 = s_strdup(comp1);
			free(lp->line);
			lp->line = comp1;
		}
	}

	for (lp = flist.head; lp; lp = lp->next) {
		if (lp->line == NULL)
			continue;
		if (strcmp(lp->line, pool) == 0) {
			BAM_DPRINTF(("%s: found pool name: %s in zpool "
			    "status\n", fcn, pool));
			break;
		}
	}

	if (lp == NULL) {
		bam_error(_("no pool name %s in zpool status\n"), pool);
		filelist_free(&flist);
		return (-1);
	}

	startlp = lp->next;
	for (i = 0, lp = startlp; lp; lp = lp->next) {
		if (lp->line == NULL)
			continue;
		if (strcmp(lp->line, "mirror") == 0)
			continue;
		if (lp->line[0] == '\0' || strcmp(lp->line, "errors:") == 0)
			break;
		i++;
		BAM_DPRINTF(("%s: counting phys slices in zpool status: %d\n",
		    fcn, i));
	}

	if (i == 0) {
		bam_error(_("no physical device in zpool status for pool=%s\n"),
		    pool);
		filelist_free(&flist);
		return (-1);
	}

	*n = i;
	*physarray = s_calloc(*n, sizeof (char *));
	for (i = 0, lp = startlp; lp; lp = lp->next) {
		if (lp->line == NULL)
			continue;
		if (strcmp(lp->line, "mirror") == 0)
			continue;
		if (strcmp(lp->line, "errors:") == 0)
			break;
		if (strncmp(lp->line, "/dev/dsk/", strlen("/dev/dsk/")) != 0 &&
		    strncmp(lp->line, "/dev/rdsk/",
		    strlen("/dev/rdsk/")) != 0)  {
			(void) snprintf(dsk, sizeof (dsk), "/dev/rdsk/%s",
			    lp->line);
		} else {
			(void) strlcpy(dsk, lp->line, sizeof (dsk));
		}
		BAM_DPRINTF(("%s: adding phys slice=%s from pool %s status\n",
		    fcn, dsk, pool));
		(*physarray)[i++] = s_strdup(dsk);
	}

	assert(i == *n);

	filelist_free(&flist);

	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	return (0);
}

static int
get_physical(char *menu_root, char ***physarray, int *n)
{
	char			*special;
	int			ret;
	const char		*fcn = "get_physical()";

	assert(menu_root);
	assert(physarray);
	assert(n);

	*physarray = NULL;
	*n = 0;

	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, menu_root));

	/* First get the device special file from /etc/mnttab */
	special = get_special(menu_root);
	INJECT_ERROR1("GET_PHYSICAL_SPECIAL", special = NULL);
	if (special == NULL) {
		bam_error(_("cannot get special file for mount-point: %s\n"),
		    menu_root);
		return (-1);
	}

	/* If already a physical device nothing to do */
	if (strncmp(special, "/dev/dsk/", strlen("/dev/dsk/")) == 0 ||
	    strncmp(special, "/dev/rdsk/", strlen("/dev/rdsk/")) == 0) {
		BAM_DPRINTF(("%s: got physical device already directly for "
		    "menu_root=%s special=%s\n", fcn, menu_root, special));
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
		*physarray = s_calloc(1, sizeof (char *));
		(*physarray)[0] = special;
		*n = 1;
		return (0);
	}

	if (is_zfs(menu_root)) {
		ret = zfs_get_physical(special, physarray, n);
	} else {
		bam_error(_("cannot derive physical device for %s (%s), "
		    "unsupported filesystem\n"), menu_root, special);
		ret = -1;
	}

	free(special);

	INJECT_ERROR1("GET_PHYSICAL_RET", ret = -1);
	if (ret == -1) {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	} else {
		int	i;
		assert (*n > 0);
		for (i = 0; i < *n; i++) {
			BAM_DPRINTF(("%s: returning physical=%s\n",
			    fcn, (*physarray)[i]));
		}
	}

	return (ret);
}

static int
is_bootdisk(char *osroot, char *physical)
{
	int			ret;
	char			*grubroot;
	char			*bootp;
	const char		*fcn = "is_bootdisk()";

	assert(osroot);
	assert(physical);

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osroot, physical));

	bootp = strstr(physical, "p0:boot");
	if (bootp)
		*bootp = '\0';
	/*
	 * We just want the BIOS mapping for menu disk.
	 * Don't pass menu_root to get_grubroot() as the
	 * check that it is used for is not relevant here.
	 * The osroot is immaterial as well - it is only used to
	 * to find create_diskmap script. Everything hinges on
	 * "physical"
	 */
	grubroot = get_grubroot(osroot, physical, NULL);

	INJECT_ERROR1("IS_BOOTDISK_GRUBROOT", grubroot = NULL);
	if (grubroot == NULL) {
		if (bam_verbose)
			bam_error(_("cannot determine BIOS disk ID 'hd?' for "
			    "disk: %s\n"), physical);
		return (0);
	}
	ret = grubroot[3] == '0';
	free(grubroot);

	BAM_DPRINTF(("%s: returning ret = %d\n", fcn, ret));

	return (ret);
}

/*
 * Check if menu is on the boot device
 * Return 0 (false) on error
 */
static int
menu_on_bootdisk(char *osroot, char *menu_root)
{
	char		**physarray;
	int		ret;
	int		n;
	int		i;
	int		on_bootdisk;
	const char	*fcn = "menu_on_bootdisk()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osroot, menu_root));

	ret = get_physical(menu_root, &physarray, &n);
	INJECT_ERROR1("MENU_ON_BOOTDISK_PHYSICAL", ret = -1);
	if (ret != 0) {
		bam_error(_("cannot get physical device special file for menu "
		    "root: %s\n"), menu_root);
		return (0);
	}

	assert(physarray);
	assert(n > 0);

	on_bootdisk = 0;
	for (i = 0; i < n; i++) {
		assert(strncmp(physarray[i], "/dev/dsk/",
		    strlen("/dev/dsk/")) == 0 ||
		    strncmp(physarray[i], "/dev/rdsk/",
		    strlen("/dev/rdsk/")) == 0);

		BAM_DPRINTF(("%s: checking if phys-device=%s is on bootdisk\n",
		    fcn, physarray[i]));
		if (is_bootdisk(osroot, physarray[i])) {
			on_bootdisk = 1;
			BAM_DPRINTF(("%s: phys-device=%s *IS* on bootdisk\n",
			    fcn, physarray[i]));
		}
	}

	free_physarray(physarray, n);

	INJECT_ERROR1("ON_BOOTDISK_YES", on_bootdisk = 1);
	INJECT_ERROR1("ON_BOOTDISK_NO", on_bootdisk = 0);
	if (on_bootdisk) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}

	return (on_bootdisk);
}

void
bam_add_line(menu_t *mp, entry_t *entry, line_t *prev, line_t *lp)
{
	const char	*fcn = "bam_add_line()";

	assert(mp);
	assert(entry);
	assert(prev);
	assert(lp);

	lp->next = prev->next;
	if (prev->next) {
		BAM_DPRINTF(("%s: previous next exists\n", fcn));
		prev->next->prev = lp;
	} else {
		BAM_DPRINTF(("%s: previous next does not exist\n", fcn));
	}
	prev->next = lp;
	lp->prev = prev;

	if (entry->end == prev) {
		BAM_DPRINTF(("%s: last line in entry\n", fcn));
		entry->end = lp;
	}
	if (mp->end == prev) {
		assert(lp->next == NULL);
		mp->end = lp;
		BAM_DPRINTF(("%s: last line in menu\n", fcn));
	}
}

/*
 * look for matching bootadm entry with specified parameters
 * Here are the rules (based on existing usage):
 * - If title is specified, match on title only
 * - Else, match on root/findroot, kernel, and module.
 *   Note that, if root_opt is non-zero, the absence of
 *   root line is considered a match.
 */
static entry_t *
find_boot_entry(
	menu_t *mp,
	char *title,
	char *kernel,
	char *findroot,
	char *root,
	char *module,
	int root_opt,
	int *entry_num)
{
	int		i;
	line_t		*lp;
	entry_t		*ent;
	const char	*fcn = "find_boot_entry()";

	if (entry_num)
		*entry_num = BAM_ERROR;

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
			    strcmp(lp->arg, title) == 0) {
				BAM_DPRINTF(("%s: matched title: %s\n",
				    fcn, title));
				break;
			}
			BAM_DPRINTF(("%s: no match title: %s, %s\n",
			    fcn, title, lp->arg));
			continue;	/* check title only */
		}

		lp = lp->next;	/* advance to root line */
		if (lp == NULL) {
			continue;
		} else if (lp->cmd != NULL &&
		    strcmp(lp->cmd, menu_cmds[FINDROOT_CMD]) == 0) {
			INJECT_ERROR1("FIND_BOOT_ENTRY_NULL_FINDROOT",
			    findroot = NULL);
			if (findroot == NULL) {
				BAM_DPRINTF(("%s: no match line has findroot, "
				    "we don't: %s\n", fcn, lp->arg));
				continue;
			}
			/* findroot command found, try match  */
			if (strcmp(lp->arg, findroot) != 0) {
				BAM_DPRINTF(("%s: no match findroot: %s, %s\n",
				    fcn, findroot, lp->arg));
				continue;
			}
			BAM_DPRINTF(("%s: matched findroot: %s\n",
			    fcn, findroot));
			lp = lp->next;	/* advance to kernel line */
		} else if (lp->cmd != NULL &&
		    strcmp(lp->cmd, menu_cmds[ROOT_CMD]) == 0) {
			INJECT_ERROR1("FIND_BOOT_ENTRY_NULL_ROOT", root = NULL);
			if (root == NULL) {
				BAM_DPRINTF(("%s: no match, line has root, we "
				    "don't: %s\n", fcn, lp->arg));
				continue;
			}
			/* root cmd found, try match */
			if (strcmp(lp->arg, root) != 0) {
				BAM_DPRINTF(("%s: no match root: %s, %s\n",
				    fcn, root, lp->arg));
				continue;
			}
			BAM_DPRINTF(("%s: matched root: %s\n", fcn, root));
			lp = lp->next;	/* advance to kernel line */
		} else {
			INJECT_ERROR1("FIND_BOOT_ENTRY_ROOT_OPT_NO",
			    root_opt = 0);
			INJECT_ERROR1("FIND_BOOT_ENTRY_ROOT_OPT_YES",
			    root_opt = 1);
			/* no root command, see if root is optional */
			if (root_opt == 0) {
				BAM_DPRINTF(("%s: root NOT optional\n", fcn));
				continue;
			}
			BAM_DPRINTF(("%s: root IS optional\n", fcn));
		}

		if (lp == NULL || lp->next == NULL) {
			continue;
		}

		if (kernel &&
		    (!check_cmd(lp->cmd, KERNEL_CMD, lp->arg, kernel))) {
			if (!(ent->flags & BAM_ENTRY_FAILSAFE) ||
			    !(ent->flags & BAM_ENTRY_DBOOT) ||
			    strcmp(kernel, DIRECT_BOOT_FAILSAFE_LINE) != 0)
				continue;

			ent->flags |= BAM_ENTRY_UPGFSKERNEL;

		}
		BAM_DPRINTF(("%s: kernel match: %s, %s\n", fcn,
		    kernel, lp->arg));

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
			BAM_DPRINTF(("%s: module match: %s, %s\n", fcn,
			    module, lp->arg));
			break;
		}

		if (strcmp(module, FAILSAFE_ARCHIVE) == 0 &&
		    (strcmp(lp->prev->arg, FAILSAFE_ARCHIVE_32) == 0 ||
		    strcmp(lp->prev->arg, FAILSAFE_ARCHIVE_64) == 0)) {
			ent->flags |= BAM_ENTRY_UPGFSMODULE;
			break;
		}

	}

	if (ent && entry_num) {
		*entry_num = i;
	}

	if (ent) {
		BAM_DPRINTF(("%s: returning ret = %d\n", fcn, i));
	} else {
		BAM_DPRINTF(("%s: returning ret = %d\n", fcn, BAM_ERROR));
	}
	return (ent);
}

static int
update_boot_entry(menu_t *mp, char *title, char *findroot, char *root,
    char *kernel, char *mod_kernel, char *module, int root_opt)
{
	int		i;
	int		change_kernel = 0;
	entry_t		*ent;
	line_t		*lp;
	line_t		*tlp;
	char		linebuf[BAM_MAXLINE];
	const char	*fcn = "update_boot_entry()";

	/* note: don't match on title, it's updated on upgrade */
	ent = find_boot_entry(mp, NULL, kernel, findroot, root, module,
	    root_opt, &i);
	if ((ent == NULL) && (bam_direct == BAM_DIRECT_DBOOT)) {
		/*
		 * We may be upgrading a kernel from multiboot to
		 * directboot.  Look for a multiboot entry. A multiboot
		 * entry will not have a findroot line.
		 */
		ent = find_boot_entry(mp, NULL, "multiboot", NULL, root,
		    MULTIBOOT_ARCHIVE, root_opt, &i);
		if (ent != NULL) {
			BAM_DPRINTF(("%s: upgrading entry from dboot to "
			    "multiboot: root = %s\n", fcn, root));
			change_kernel = 1;
		}
	} else if (ent) {
		BAM_DPRINTF(("%s: found entry with matching findroot: %s\n",
		    fcn, findroot));
	}

	if (ent == NULL) {
		BAM_DPRINTF(("%s: boot entry not found in menu. Creating "
		    "new entry, findroot = %s\n", fcn, findroot));
		return (add_boot_entry(mp, title, findroot,
		    kernel, mod_kernel, module, NULL));
	}

	/* replace title of existing entry and update findroot line */
	lp = ent->start;
	lp = lp->next;	/* title line */
	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[TITLE_CMD], menu_cmds[SEP_CMD], title);
	free(lp->arg);
	free(lp->line);
	lp->arg = s_strdup(title);
	lp->line = s_strdup(linebuf);
	BAM_DPRINTF(("%s: changing title to: %s\n", fcn, title));

	tlp = lp;	/* title line */
	lp = lp->next;	/* root line */

	/* if no root or findroot command, create a new line_t */
	if ((lp->cmd != NULL) && (strcmp(lp->cmd, menu_cmds[ROOT_CMD]) != 0 &&
	    strcmp(lp->cmd, menu_cmds[FINDROOT_CMD]) != 0)) {
		lp = s_calloc(1, sizeof (line_t));
		bam_add_line(mp, ent, tlp, lp);
	} else {
		if (lp->cmd != NULL)
			free(lp->cmd);

		free(lp->sep);
		free(lp->arg);
		free(lp->line);
	}

	lp->cmd = s_strdup(menu_cmds[FINDROOT_CMD]);
	lp->sep = s_strdup(menu_cmds[SEP_CMD]);
	lp->arg = s_strdup(findroot);
	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[FINDROOT_CMD], menu_cmds[SEP_CMD], findroot);
	lp->line = s_strdup(linebuf);
	BAM_DPRINTF(("%s: adding findroot line: %s\n", fcn, findroot));

	/* kernel line */
	lp = lp->next;

	if (ent->flags & BAM_ENTRY_UPGFSKERNEL) {
		char		*params = NULL;

		params = strstr(lp->line, "-s");
		if (params != NULL)
			(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s%s",
			    menu_cmds[KERNEL_DOLLAR_CMD], menu_cmds[SEP_CMD],
			    kernel, params+2);
		else
			(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
			    menu_cmds[KERNEL_DOLLAR_CMD], menu_cmds[SEP_CMD],
			    kernel);

		if (lp->cmd != NULL)
			free(lp->cmd);

		free(lp->arg);
		free(lp->line);
		lp->cmd = s_strdup(menu_cmds[KERNEL_DOLLAR_CMD]);
		lp->arg = s_strdup(strstr(linebuf, "/"));
		lp->line = s_strdup(linebuf);
		ent->flags &= ~BAM_ENTRY_UPGFSKERNEL;
		BAM_DPRINTF(("%s: adding new kernel$ line: %s\n",
		    fcn, lp->prev->cmd));
	}

	if (change_kernel) {
		/*
		 * We're upgrading from multiboot to directboot.
		 */
		if (lp->cmd != NULL &&
		    strcmp(lp->cmd, menu_cmds[KERNEL_CMD]) == 0) {
			(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
			    menu_cmds[KERNEL_DOLLAR_CMD], menu_cmds[SEP_CMD],
			    kernel);
			free(lp->cmd);
			free(lp->arg);
			free(lp->line);
			lp->cmd = s_strdup(menu_cmds[KERNEL_DOLLAR_CMD]);
			lp->arg = s_strdup(kernel);
			lp->line = s_strdup(linebuf);
			lp = lp->next;
			BAM_DPRINTF(("%s: adding new kernel$ line: %s\n",
			    fcn, kernel));
		}
		if (lp->cmd != NULL &&
		    strcmp(lp->cmd, menu_cmds[MODULE_CMD]) == 0) {
			(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
			    menu_cmds[MODULE_DOLLAR_CMD], menu_cmds[SEP_CMD],
			    module);
			free(lp->cmd);
			free(lp->arg);
			free(lp->line);
			lp->cmd = s_strdup(menu_cmds[MODULE_DOLLAR_CMD]);
			lp->arg = s_strdup(module);
			lp->line = s_strdup(linebuf);
			lp = lp->next;
			BAM_DPRINTF(("%s: adding new module$ line: %s\n",
			    fcn, module));
		}
	}

	/* module line */
	lp = lp->next;

	if (ent->flags & BAM_ENTRY_UPGFSMODULE) {
		if (lp->cmd != NULL &&
		    strcmp(lp->cmd, menu_cmds[MODULE_CMD]) == 0) {
			(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
			    menu_cmds[MODULE_DOLLAR_CMD], menu_cmds[SEP_CMD],
			    module);
			free(lp->cmd);
			free(lp->arg);
			free(lp->line);
			lp->cmd = s_strdup(menu_cmds[MODULE_DOLLAR_CMD]);
			lp->arg = s_strdup(module);
			lp->line = s_strdup(linebuf);
			lp = lp->next;
			ent->flags &= ~BAM_ENTRY_UPGFSMODULE;
			BAM_DPRINTF(("%s: adding new module$ line: %s\n",
			    fcn, module));
		}
	}

	BAM_DPRINTF(("%s: returning ret = %d\n", fcn, i));
	return (i);
}

int
root_optional(char *osroot, char *menu_root)
{
	char			*ospecial;
	char			*mspecial;
	char			*slash;
	int			root_opt;
	int			ret1;
	int			ret2;
	const char		*fcn = "root_optional()";

	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn, osroot, menu_root));

	/*
	 * For all filesystems except ZFS, a straight compare of osroot
	 * and menu_root will tell us if root is optional.
	 * For ZFS, the situation is complicated by the fact that
	 * menu_root and osroot are always different
	 */
	ret1 = is_zfs(osroot);
	ret2 = is_zfs(menu_root);
	INJECT_ERROR1("ROOT_OPT_NOT_ZFS", ret1 = 0);
	if (!ret1 || !ret2) {
		BAM_DPRINTF(("%s: one or more non-ZFS filesystems (%s, %s)\n",
		    fcn, osroot, menu_root));
		root_opt = (strcmp(osroot, menu_root) == 0);
		goto out;
	}

	ospecial = get_special(osroot);
	INJECT_ERROR1("ROOT_OPTIONAL_OSPECIAL", ospecial = NULL);
	if (ospecial == NULL) {
		bam_error(_("failed to get special file for osroot: %s\n"),
		    osroot);
		return (0);
	}
	BAM_DPRINTF(("%s: ospecial=%s for osroot=%s\n", fcn, ospecial, osroot));

	mspecial = get_special(menu_root);
	INJECT_ERROR1("ROOT_OPTIONAL_MSPECIAL", mspecial = NULL);
	if (mspecial == NULL) {
		bam_error(_("failed to get special file for menu_root: %s\n"),
		    menu_root);
		free(ospecial);
		return (0);
	}
	BAM_DPRINTF(("%s: mspecial=%s for menu_root=%s\n",
	    fcn, mspecial, menu_root));

	slash = strchr(ospecial, '/');
	if (slash)
		*slash = '\0';
	BAM_DPRINTF(("%s: FIXED ospecial=%s for osroot=%s\n",
	    fcn, ospecial, osroot));

	root_opt = (strcmp(ospecial, mspecial) == 0);

	free(ospecial);
	free(mspecial);

out:
	INJECT_ERROR1("ROOT_OPTIONAL_NO", root_opt = 0);
	INJECT_ERROR1("ROOT_OPTIONAL_YES", root_opt = 1);
	if (root_opt) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}

	return (root_opt);
}

/*ARGSUSED*/
static error_t
update_entry(menu_t *mp, char *menu_root, char *osdev)
{
	int		entry;
	char		*grubsign;
	char		*grubroot;
	char		*title;
	char		osroot[PATH_MAX];
	char		*failsafe_kernel = NULL;
	struct stat	sbuf;
	char		failsafe[256];
	char		failsafe_64[256];
	int		ret;
	const char	*fcn = "update_entry()";

	assert(mp);
	assert(menu_root);
	assert(osdev);
	assert(bam_root);

	BAM_DPRINTF(("%s: entered. args: %s %s %s\n", fcn, menu_root, osdev,
	    bam_root));

	(void) strlcpy(osroot, bam_root, sizeof (osroot));

	title = get_title(osroot);
	assert(title);

	grubsign = get_grubsign(osroot, osdev);
	INJECT_ERROR1("GET_GRUBSIGN_FAIL", grubsign = NULL);
	if (grubsign == NULL) {
		bam_error(_("failed to get grubsign for root: %s, device %s\n"),
		    osroot, osdev);
		return (BAM_ERROR);
	}

	/*
	 * It is not a fatal error if get_grubroot() fails
	 * We no longer rely on biosdev to populate the
	 * menu
	 */
	grubroot = get_grubroot(osroot, osdev, menu_root);
	INJECT_ERROR1("GET_GRUBROOT_FAIL", grubroot = NULL);
	if (grubroot) {
		BAM_DPRINTF(("%s: get_grubroot success. osroot=%s, osdev=%s, "
		    "menu_root=%s\n", fcn, osroot, osdev, menu_root));
	} else {
		BAM_DPRINTF(("%s: get_grubroot failed. osroot=%s, osdev=%s, "
		    "menu_root=%s\n", fcn, osroot, osdev, menu_root));
	}

	/* add the entry for normal Solaris */
	INJECT_ERROR1("UPDATE_ENTRY_MULTIBOOT",
	    bam_direct = BAM_DIRECT_MULTIBOOT);
	if (bam_direct == BAM_DIRECT_DBOOT) {
		entry = update_boot_entry(mp, title, grubsign, grubroot,
		    (bam_zfs ? DIRECT_BOOT_KERNEL_ZFS : DIRECT_BOOT_KERNEL),
		    NULL, DIRECT_BOOT_ARCHIVE,
		    root_optional(osroot, menu_root));
		BAM_DPRINTF(("%s: updated boot entry bam_zfs=%d, "
		    "grubsign = %s\n", fcn, bam_zfs, grubsign));
		if ((entry != BAM_ERROR) && (bam_is_hv == BAM_HV_PRESENT)) {
			(void) update_boot_entry(mp, NEW_HV_ENTRY, grubsign,
			    grubroot, XEN_MENU, bam_zfs ?
			    XEN_KERNEL_MODULE_LINE_ZFS : XEN_KERNEL_MODULE_LINE,
			    DIRECT_BOOT_ARCHIVE,
			    root_optional(osroot, menu_root));
			BAM_DPRINTF(("%s: updated HV entry bam_zfs=%d, "
			    "grubsign = %s\n", fcn, bam_zfs, grubsign));
		}
	} else {
		entry = update_boot_entry(mp, title, grubsign, grubroot,
		    MULTI_BOOT, NULL, MULTIBOOT_ARCHIVE,
		    root_optional(osroot, menu_root));

		BAM_DPRINTF(("%s: updated MULTIBOOT entry grubsign = %s\n",
		    fcn, grubsign));
	}

	/*
	 * Add the entry for failsafe archive.  On a bfu'd system, the
	 * failsafe may be different than the installed kernel.
	 */
	(void) snprintf(failsafe, sizeof (failsafe), "%s%s",
	    osroot, FAILSAFE_ARCHIVE_32);
	(void) snprintf(failsafe_64, sizeof (failsafe_64), "%s%s",
	    osroot, FAILSAFE_ARCHIVE_64);

	/*
	 * Check if at least one of the two archives exists
	 * Using $ISADIR as the default line, we have an entry which works
	 * for both the cases.
	 */

	if (stat(failsafe, &sbuf) == 0 || stat(failsafe_64, &sbuf) == 0) {

		/* Figure out where the kernel line should point */
		(void) snprintf(failsafe, sizeof (failsafe), "%s%s", osroot,
		    DIRECT_BOOT_FAILSAFE_32);
		(void) snprintf(failsafe_64, sizeof (failsafe_64), "%s%s",
		    osroot, DIRECT_BOOT_FAILSAFE_64);
		if (stat(failsafe, &sbuf) == 0 ||
		    stat(failsafe_64, &sbuf) == 0) {
			failsafe_kernel = DIRECT_BOOT_FAILSAFE_LINE;
		} else {
			(void) snprintf(failsafe, sizeof (failsafe), "%s%s",
			    osroot, MULTI_BOOT_FAILSAFE);
			if (stat(failsafe, &sbuf) == 0) {
				failsafe_kernel = MULTI_BOOT_FAILSAFE_LINE;
			}
		}
		if (failsafe_kernel != NULL) {
			(void) update_boot_entry(mp, FAILSAFE_TITLE, grubsign,
			    grubroot, failsafe_kernel, NULL, FAILSAFE_ARCHIVE,
			    root_optional(osroot, menu_root));
			BAM_DPRINTF(("%s: updated FAILSAFE entry "
			    "failsafe_kernel = %s\n", fcn, failsafe_kernel));
		}
	}
	free(grubroot);

	INJECT_ERROR1("UPDATE_ENTRY_ERROR", entry = BAM_ERROR);
	if (entry == BAM_ERROR) {
		bam_error(_("failed to add boot entry with title=%s, grub "
		    "signature=%s\n"), title, grubsign);
		free(grubsign);
		return (BAM_ERROR);
	}
	free(grubsign);

	update_numbering(mp);
	ret = set_global(mp, menu_cmds[DEFAULT_CMD], entry);
	INJECT_ERROR1("SET_DEFAULT_ERROR", ret = BAM_ERROR);
	if (ret == BAM_ERROR) {
		bam_error(_("failed to set GRUB menu default to %d\n"), entry);
	}
	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	return (BAM_WRITE);
}

static void
save_default_entry(menu_t *mp, const char *which)
{
	int		lineNum;
	int		entryNum;
	int		entry = 0;	/* default is 0 */
	char		linebuf[BAM_MAXLINE];
	line_t		*lp = mp->curdefault;
	const char	*fcn = "save_default_entry()";

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
	BAM_DPRINTF(("%s: saving default to: %s\n", fcn, linebuf));
	line_parser(mp, linebuf, &lineNum, &entryNum);
	BAM_DPRINTF(("%s: saved default to lineNum=%d, entryNum=%d\n", fcn,
	    lineNum, entryNum));
}

static void
restore_default_entry(menu_t *mp, const char *which, line_t *lp)
{
	int		entry;
	char		*str;
	const char	*fcn = "restore_default_entry()";

	if (lp == NULL) {
		BAM_DPRINTF(("%s: NULL saved default\n", fcn));
		return;		/* nothing to restore */
	}

	BAM_DPRINTF(("%s: saved default string: %s\n", fcn, which));

	str = lp->arg + strlen(which);
	entry = s_strtol(str);
	(void) set_global(mp, menu_cmds[DEFAULT_CMD], entry);

	BAM_DPRINTF(("%s: restored default to entryNum: %d\n", fcn, entry));

	/* delete saved old default line */
	unlink_line(mp, lp);
	line_free(lp);
}

/*
 * This function is for supporting reboot with args.
 * The opt value can be:
 * NULL		delete temp entry, if present
 * entry=<n>	switches default entry to <n>
 * else		treated as boot-args and setup a temperary menu entry
 *		and make it the default
 * Note that we are always rebooting the current OS instance
 * so osroot == / always.
 */
#define	REBOOT_TITLE	"Solaris_reboot_transient"

/*ARGSUSED*/
static error_t
update_temp(menu_t *mp, char *dummy, char *opt)
{
	int		entry;
	char		*osdev;
	char		*fstype;
	char		*sign;
	char		*opt_ptr;
	char		*path;
	char		kernbuf[BUFSIZ];
	char		args_buf[BUFSIZ];
	char		signbuf[PATH_MAX];
	int		ret;
	const char	*fcn = "update_temp()";

	assert(mp);
	assert(dummy == NULL);

	/* opt can be NULL */
	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, opt ? opt : "<NULL>"));
	BAM_DPRINTF(("%s: bam_alt_root: %d, bam_root: %s\n", fcn,
	    bam_alt_root, bam_root));

	if (bam_alt_root || bam_rootlen != 1 ||
	    strcmp(bam_root, "/") != 0 ||
	    strcmp(rootbuf, "/") != 0) {
		bam_error(_("an alternate root (%s) cannot be used with this "
		    "sub-command\n"), bam_root);
		return (BAM_ERROR);
	}

	/* If no option, delete exiting reboot menu entry */
	if (opt == NULL) {
		entry_t		*ent;
		BAM_DPRINTF(("%s: opt is NULL\n", fcn));
		ent = find_boot_entry(mp, REBOOT_TITLE, NULL, NULL,
		    NULL, NULL, 0, &entry);
		if (ent == NULL) {	/* not found is ok */
			BAM_DPRINTF(("%s: transient entry not found\n", fcn));
			return (BAM_SUCCESS);
		}
		(void) delete_boot_entry(mp, entry, DBE_PRINTERR);
		restore_default_entry(mp, BAM_OLDDEF, mp->olddefault);
		mp->olddefault = NULL;
		BAM_DPRINTF(("%s: restored old default\n", fcn));
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
		return (BAM_WRITE);
	}

	/* if entry= is specified, set the default entry */
	if (strncmp(opt, "entry=", strlen("entry=")) == 0) {
		int entryNum = s_strtol(opt + strlen("entry="));
		BAM_DPRINTF(("%s: opt has entry=: %s\n", fcn, opt));
		if (selector(mp, opt, &entry, NULL) == BAM_SUCCESS) {
			/* this is entry=# option */
			ret = set_global(mp, menu_cmds[DEFAULT_CMD], entry);
			BAM_DPRINTF(("%s: default set to %d, "
			    "set_default ret=%d\n", fcn, entry, ret));
			return (ret);
		} else {
			bam_error(_("failed to set GRUB menu default to %d\n"),
			    entryNum);
			return (BAM_ERROR);
		}
	}

	/*
	 * add a new menu entry based on opt and make it the default
	 */

	fstype = get_fstype("/");
	INJECT_ERROR1("REBOOT_FSTYPE_NULL", fstype = NULL);
	if (fstype == NULL) {
		bam_error(_("failed to determine filesystem type for \"/\". "
		    "Reboot with \narguments failed.\n"));
		return (BAM_ERROR);
	}

	osdev = get_special("/");
	INJECT_ERROR1("REBOOT_SPECIAL_NULL", osdev = NULL);
	if (osdev == NULL) {
		free(fstype);
		bam_error(_("failed to find device special file for \"/\". "
		    "Reboot with \narguments failed.\n"));
		return (BAM_ERROR);
	}

	sign = find_existing_sign("/", osdev, fstype);
	INJECT_ERROR1("REBOOT_SIGN_NULL", sign = NULL);
	if (sign == NULL) {
		free(fstype);
		free(osdev);
		bam_error(_("failed to find boot signature. Reboot with "
		    "arguments failed.\n"));
		return (BAM_ERROR);
	}

	free(osdev);
	(void) strlcpy(signbuf, sign, sizeof (signbuf));
	free(sign);

	assert(strchr(signbuf, '(') == NULL && strchr(signbuf, ',') == NULL &&
	    strchr(signbuf, ')') == NULL);

	/*
	 * There is no alternate root while doing reboot with args
	 * This version of bootadm is only delivered with a DBOOT
	 * version of Solaris.
	 */
	INJECT_ERROR1("REBOOT_NOT_DBOOT", bam_direct = BAM_DIRECT_MULTIBOOT);
	if (bam_direct != BAM_DIRECT_DBOOT) {
		free(fstype);
		bam_error(_("the root filesystem is not a dboot Solaris "
		    "instance. \nThis version of bootadm is not supported "
		    "on this version of Solaris.\n"));
		return (BAM_ERROR);
	}

	/* add an entry for Solaris reboot */
	if (opt[0] == '-') {
		/* It's an option - first see if boot-file is set */
		ret = get_kernel(mp, KERNEL_CMD, kernbuf, sizeof (kernbuf));
		INJECT_ERROR1("REBOOT_GET_KERNEL", ret = BAM_ERROR);
		if (ret != BAM_SUCCESS) {
			free(fstype);
			bam_error(_("reboot with arguments: error querying "
			    "current boot-file settings\n"));
			return (BAM_ERROR);
		}
		if (kernbuf[0] == '\0')
			(void) strlcpy(kernbuf, DIRECT_BOOT_KERNEL,
			    sizeof (kernbuf));
		/*
		 * If this is a zfs file system and kernbuf does not
		 * have "-B $ZFS-BOOTFS" string yet, add it.
		 */
		if (strcmp(fstype, "zfs") == 0 && !strstr(kernbuf, ZFS_BOOT)) {
			(void) strlcat(kernbuf, " ", sizeof (kernbuf));
			(void) strlcat(kernbuf, ZFS_BOOT, sizeof (kernbuf));
		}
		(void) strlcat(kernbuf, " ", sizeof (kernbuf));
		(void) strlcat(kernbuf, opt, sizeof (kernbuf));
		BAM_DPRINTF(("%s: reboot with args, option specified: "
		    "kern=%s\n", fcn, kernbuf));
	} else if (opt[0] == '/') {
		/* It's a full path, so write it out. */
		(void) strlcpy(kernbuf, opt, sizeof (kernbuf));

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
			ret = get_kernel(mp, ARGS_CMD, args_buf,
			    sizeof (args_buf));
			INJECT_ERROR1("REBOOT_GET_ARGS", ret = BAM_ERROR);
			if (ret != BAM_SUCCESS) {
				free(fstype);
				bam_error(_("reboot with arguments: error "
				    "querying current boot-args settings\n"));
				return (BAM_ERROR);
			}

			if (args_buf[0] != '\0') {
				(void) strlcat(kernbuf, " ", sizeof (kernbuf));
				(void) strlcat(kernbuf, args_buf,
				    sizeof (kernbuf));
			}
		}
		BAM_DPRINTF(("%s: reboot with args, abspath specified: "
		    "kern=%s\n", fcn, kernbuf));
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
			(void) strlcpy(kernbuf, path, sizeof (kernbuf));
			free(path);

			/*
			 * If there were options given, use those.
			 * Otherwise, copy over the default options.
			 */
			if (opt_ptr != NULL) {
				/* Restore the space in opt string */
				*opt_ptr = ' ';
				(void) strlcat(kernbuf, opt_ptr,
				    sizeof (kernbuf));
			} else {
				ret = get_kernel(mp, ARGS_CMD, args_buf,
				    sizeof (args_buf));
				INJECT_ERROR1("UPDATE_TEMP_PARTIAL_ARGS",
				    ret = BAM_ERROR);
				if (ret != BAM_SUCCESS) {
					free(fstype);
					bam_error(_("reboot with arguments: "
					    "error querying current boot-args "
					    "settings\n"));
					return (BAM_ERROR);
				}

				if (args_buf[0] != '\0') {
					(void) strlcat(kernbuf, " ",
					    sizeof (kernbuf));
					(void) strlcat(kernbuf,
					    args_buf, sizeof (kernbuf));
				}
			}
			BAM_DPRINTF(("%s: resolved partial path: %s\n",
			    fcn, kernbuf));
		} else {
			free(fstype);
			bam_error(_("unable to expand %s to a full file"
			    " path.\n"), opt);
			bam_print_stderr(_("Rebooting with default kernel "
			    "and options.\n"));
			return (BAM_ERROR);
		}
	}
	free(fstype);
	entry = add_boot_entry(mp, REBOOT_TITLE, signbuf, kernbuf,
	    NULL, NULL, NULL);
	INJECT_ERROR1("REBOOT_ADD_BOOT_ENTRY", entry = BAM_ERROR);
	if (entry == BAM_ERROR) {
		bam_error(_("Cannot update menu. Cannot reboot with "
		    "requested arguments\n"));
		return (BAM_ERROR);
	}

	save_default_entry(mp, BAM_OLDDEF);
	ret = set_global(mp, menu_cmds[DEFAULT_CMD], entry);
	INJECT_ERROR1("REBOOT_SET_GLOBAL", ret = BAM_ERROR);
	if (ret == BAM_ERROR) {
		bam_error(_("reboot with arguments: setting GRUB menu default "
		    "to %d failed\n"), entry);
	}
	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	return (BAM_WRITE);
}

error_t
set_global(menu_t *mp, char *globalcmd, int val)
{
	line_t		*lp;
	line_t		*found;
	line_t		*last;
	char		*cp;
	char		*str;
	char		prefix[BAM_MAXLINE];
	size_t		len;
	const char	*fcn = "set_global()";

	assert(mp);
	assert(globalcmd);

	if (strcmp(globalcmd, menu_cmds[DEFAULT_CMD]) == 0) {
		INJECT_ERROR1("SET_GLOBAL_VAL_NEG", val = -1);
		INJECT_ERROR1("SET_GLOBAL_MENU_EMPTY", mp->end = NULL);
		INJECT_ERROR1("SET_GLOBAL_VAL_TOO_BIG", val = 100);
		if (val < 0 || mp->end == NULL || val > mp->end->entryNum) {
			(void) snprintf(prefix, sizeof (prefix), "%d", val);
			bam_error(_("invalid boot entry number: %s\n"), prefix);
			return (BAM_ERROR);
		}
	}

	found = last = NULL;
	for (lp = mp->start; lp; lp = lp->next) {
		if (lp->flags != BAM_GLOBAL)
			continue;

		last = lp; /* track the last global found */

		INJECT_ERROR1("SET_GLOBAL_NULL_CMD", lp->cmd = NULL);
		if (lp->cmd == NULL) {
			bam_error(_("no command at line %d\n"), lp->lineNum);
			continue;
		}
		if (strcmp(globalcmd, lp->cmd) != 0)
			continue;

		BAM_DPRINTF(("%s: found matching global command: %s\n",
		    fcn, globalcmd));

		if (found) {
			bam_error(_("duplicate command %s at line %d of "
			    "%sboot/grub/menu.lst\n"), globalcmd,
			    lp->lineNum, bam_root);
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
		BAM_DPRINTF(("%s: wrote new global line: %s\n", fcn, lp->line));
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
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

	BAM_DPRINTF(("%s: replaced global line with: %s\n", fcn, found->line));
	BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
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
	int		new_path_len;
	char		*new_path;
	char		new_path2[PATH_MAX];
	struct stat	sb;
	const char	*fcn = "expand_path()";

	new_path_len = strlen(partial_path) + 64;
	new_path = s_calloc(1, new_path_len);

	/* First, try the simplest case - something like "kernel/unix" */
	(void) snprintf(new_path, new_path_len, "/platform/i86pc/%s",
	    partial_path);
	if (stat(new_path, &sb) == 0) {
		BAM_DPRINTF(("%s: expanded path: %s\n", fcn, new_path));
		return (new_path);
	}

	if (strcmp(partial_path, "kmdb") == 0) {
		(void) snprintf(new_path, new_path_len, "%s -k",
		    DIRECT_BOOT_KERNEL);
		BAM_DPRINTF(("%s: expanded path: %s\n", fcn, new_path));
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
		BAM_DPRINTF(("%s: expanded path: %s\n", fcn, new_path));
		return (new_path);
	}

	free(new_path);
	BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	return (NULL);
}

/*
 * The kernel cmd and arg have been changed, so
 * check whether the archive line needs to change.
 */
static void
set_archive_line(entry_t *entryp, line_t *kernelp)
{
	line_t		*lp = entryp->start;
	char		*new_archive;
	menu_cmd_t	m_cmd;
	const char	*fcn = "set_archive_line()";

	for (; lp != NULL; lp = lp->next) {
		if (lp->cmd != NULL && strncmp(lp->cmd, menu_cmds[MODULE_CMD],
		    sizeof (menu_cmds[MODULE_CMD]) - 1) == 0) {
			break;
		}

		INJECT_ERROR1("SET_ARCHIVE_LINE_END_ENTRY", lp = entryp->end);
		if (lp == entryp->end) {
			BAM_DPRINTF(("%s: no module/archive line for entry: "
			    "%d\n", fcn, entryp->entryNum));
			return;
		}
	}
	INJECT_ERROR1("SET_ARCHIVE_LINE_END_MENU", lp = NULL);
	if (lp == NULL) {
		BAM_DPRINTF(("%s: no module/archive line for entry: %d\n",
		    fcn, entryp->entryNum));
		return;
	}

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

	if (strcmp(lp->arg, new_archive) == 0) {
		BAM_DPRINTF(("%s: no change for line: %s\n", fcn, lp->arg));
		return;
	}

	if (lp->cmd != NULL && strcmp(lp->cmd, menu_cmds[m_cmd]) != 0) {
		free(lp->cmd);
		lp->cmd = s_strdup(menu_cmds[m_cmd]);
	}

	free(lp->arg);
	lp->arg = s_strdup(new_archive);
	update_line(lp);
	BAM_DPRINTF(("%s: replaced for line: %s\n", fcn, lp->line));
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
get_set_kernel(
	menu_t *mp,
	menu_cmd_t optnum,
	char *path,
	char *buf,
	size_t bufsize)
{
	int		entryNum;
	int		rv = BAM_SUCCESS;
	int		free_new_path = 0;
	entry_t		*entryp;
	line_t		*ptr;
	line_t		*kernelp;
	char		*new_arg;
	char		*old_args;
	char		*space;
	char		*new_path;
	char		old_space;
	size_t		old_kernel_len = 0;
	size_t		new_str_len;
	char		*fstype;
	char		*osdev;
	char		*sign;
	char		signbuf[PATH_MAX];
	int		ret;
	const char	*fcn = "get_set_kernel()";

	assert(bufsize > 0);

	ptr = kernelp = NULL;
	new_arg = old_args = space = NULL;
	new_path = NULL;
	buf[0] = '\0';

	INJECT_ERROR1("GET_SET_KERNEL_NOT_DBOOT",
	    bam_direct = BAM_DIRECT_MULTIBOOT);
	if (bam_direct != BAM_DIRECT_DBOOT) {
		bam_error(_("bootadm set-menu %s may only be run on "
		    "directboot kernels.\n"),
		    optnum == KERNEL_CMD ? "kernel" : "args");
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
			bam_error(_("Default /boot/grub/menu.lst entry is not "
			    "controlled by bootadm.  Exiting\n"));
			return (BAM_ERROR);
		}
	}

	entryp = find_boot_entry(mp, BOOTENV_RC_TITLE, NULL, NULL, NULL, NULL,
	    0, &entryNum);

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
			bam_error(_("no kernel line found in entry %d\n"),
			    entryNum);
			return (BAM_ERROR);
		}

		old_kernel_len = strcspn(kernelp->arg, " \t");
		space = old_args = kernelp->arg + old_kernel_len;
		while ((*old_args == ' ') || (*old_args == '\t'))
			old_args++;
	}

	if (path == NULL) {
		if (entryp == NULL) {
			BAM_DPRINTF(("%s: no RC entry, nothing to report\n",
			    fcn));
			BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
			return (BAM_SUCCESS);
		}
		assert(kernelp);
		if (optnum == ARGS_CMD) {
			if (old_args[0] != '\0') {
				(void) strlcpy(buf, old_args, bufsize);
				BAM_DPRINTF(("%s: read menu boot-args: %s\n",
				    fcn, buf));
			}
		} else {
			/*
			 * We need to print the kernel, so we just turn the
			 * first space into a '\0' and print the beginning.
			 * We don't print anything if it's the default kernel.
			 */
			old_space = *space;
			*space = '\0';
			if (strcmp(kernelp->arg, DIRECT_BOOT_KERNEL) != 0) {
				(void) strlcpy(buf, kernelp->arg, bufsize);
				BAM_DPRINTF(("%s: read menu boot-file: %s\n",
				    fcn, buf));
			}
			*space = old_space;
		}
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
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
			BAM_DPRINTF(("%s: no reset, already has default\n",
			    fcn));
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
			(void) delete_boot_entry(mp, entryNum, DBE_PRINTERR);
			restore_default_entry(mp, BAM_OLD_RC_DEF,
			    mp->old_rc_default);
			mp->old_rc_default = NULL;
			rv = BAM_WRITE;
			BAM_DPRINTF(("%s: resetting to default\n", fcn));
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
			BAM_DPRINTF(("%s: reset kernel to default, but "
			    "retained old args: %s\n", fcn, kernelp->arg));
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
			BAM_DPRINTF(("%s: reset args to default, but retained "
			    "old kernel: %s\n", fcn, kernelp->arg));
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
			bam_error(_("unable to expand %s to a full file "
			    "path.\n"), path);
			BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
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
		fstype = get_fstype("/");
		INJECT_ERROR1("GET_SET_KERNEL_FSTYPE", fstype = NULL);
		if (fstype == NULL) {
			bam_error(_("cannot determine filesystem type for "
			    "\"/\".\nCannot generate GRUB menu entry with "
			    "EEPROM arguments.\n"));
			rv = BAM_ERROR;
			goto done;
		}

		osdev = get_special("/");
		INJECT_ERROR1("GET_SET_KERNEL_SPECIAL", osdev = NULL);
		if (osdev == NULL) {
			free(fstype);
			bam_error(_("cannot determine device special file for "
			    "\"/\".\nCannot generate GRUB menu entry with "
			    "EEPROM arguments.\n"));
			rv = BAM_ERROR;
			goto done;
		}

		sign = find_existing_sign("/", osdev, fstype);
		INJECT_ERROR1("GET_SET_KERNEL_SIGN", sign = NULL);
		if (sign == NULL) {
			free(fstype);
			free(osdev);
			bam_error(_("cannot determine boot signature for "
			    "\"/\".\nCannot generate GRUB menu entry with "
			    "EEPROM arguments.\n"));
			rv = BAM_ERROR;
			goto done;
		}

		free(osdev);
		(void) strlcpy(signbuf, sign, sizeof (signbuf));
		free(sign);
		assert(strchr(signbuf, '(') == NULL &&
		    strchr(signbuf, ',') == NULL &&
		    strchr(signbuf, ')') == NULL);

		if (optnum == KERNEL_CMD) {
			if (strcmp(fstype, "zfs") == 0) {
				new_str_len = strlen(new_path) +
				    strlen(ZFS_BOOT) + 8;
				new_arg = s_calloc(1, new_str_len);
				(void) snprintf(new_arg, new_str_len, "%s %s",
				    new_path, ZFS_BOOT);
				BAM_DPRINTF(("%s: new kernel=%s\n", fcn,
				    new_arg));
				entryNum = add_boot_entry(mp, BOOTENV_RC_TITLE,
				    signbuf, new_arg, NULL, NULL, NULL);
				free(new_arg);
			} else {
				BAM_DPRINTF(("%s: new kernel=%s\n", fcn,
				    new_path));
				entryNum = add_boot_entry(mp, BOOTENV_RC_TITLE,
				    signbuf, new_path, NULL, NULL, NULL);
			}
		} else {
			new_str_len = strlen(path) + 8;
			if (strcmp(fstype, "zfs") == 0) {
				new_str_len += strlen(DIRECT_BOOT_KERNEL_ZFS);
				new_arg = s_calloc(1, new_str_len);
				(void) snprintf(new_arg, new_str_len, "%s %s",
				    DIRECT_BOOT_KERNEL_ZFS, path);
			} else {
				new_str_len += strlen(DIRECT_BOOT_KERNEL);
				new_arg = s_calloc(1, new_str_len);
				(void) snprintf(new_arg, new_str_len, "%s %s",
				    DIRECT_BOOT_KERNEL, path);
			}

			BAM_DPRINTF(("%s: new args=%s\n", fcn, new_arg));
			entryNum = add_boot_entry(mp, BOOTENV_RC_TITLE,
			    signbuf, new_arg, NULL, DIRECT_BOOT_ARCHIVE, NULL);
			free(new_arg);
		}
		free(fstype);
		INJECT_ERROR1("GET_SET_KERNEL_ADD_BOOT_ENTRY",
		    entryNum = BAM_ERROR);
		if (entryNum == BAM_ERROR) {
			bam_error(_("failed to add boot entry: %s\n"),
			    BOOTENV_RC_TITLE);
			rv = BAM_ERROR;
			goto done;
		}
		save_default_entry(mp, BAM_OLD_RC_DEF);
		ret = set_global(mp, menu_cmds[DEFAULT_CMD], entryNum);
		INJECT_ERROR1("GET_SET_KERNEL_SET_GLOBAL", ret = BAM_ERROR);
		if (ret == BAM_ERROR) {
			bam_error(_("failed to set default to: %d\n"),
			    entryNum);
		}
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
		BAM_DPRINTF(("%s: rc line exists, replaced kernel, same "
		    "args: %s\n", fcn, kernelp->arg));
	} else {
		new_str_len = old_kernel_len + strlen(path) + 8;
		new_arg = s_calloc(1, new_str_len);
		(void) strncpy(new_arg, kernelp->arg, old_kernel_len);
		(void) strlcat(new_arg, " ", new_str_len);
		(void) strlcat(new_arg, path, new_str_len);
		free(kernelp->arg);
		kernelp->arg = new_arg;
		BAM_DPRINTF(("%s: rc line exists, same kernel, but new "
		    "args: %s\n", fcn, kernelp->arg));
	}
	rv = BAM_WRITE;

done:
	if ((rv == BAM_WRITE) && kernelp)
		update_line(kernelp);
	if (free_new_path)
		free(new_path);
	if (rv == BAM_WRITE) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}
	return (rv);
}

static error_t
get_kernel(menu_t *mp, menu_cmd_t optnum, char *buf, size_t bufsize)
{
	const char	*fcn = "get_kernel()";
	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, menu_cmds[optnum]));
	return (get_set_kernel(mp, optnum, NULL, buf, bufsize));
}

static error_t
set_kernel(menu_t *mp, menu_cmd_t optnum, char *path, char *buf, size_t bufsize)
{
	const char	*fcn = "set_kernel()";
	assert(path != NULL);
	BAM_DPRINTF(("%s: entered. args: %s %s\n", fcn,
	    menu_cmds[optnum], path));
	return (get_set_kernel(mp, optnum, path, buf, bufsize));
}

/*ARGSUSED*/
static error_t
set_option(menu_t *mp, char *dummy, char *opt)
{
	int		optnum;
	int		optval;
	char		*val;
	char		buf[BUFSIZ] = "";
	error_t		rv;
	const char	*fcn = "set_option()";

	assert(mp);
	assert(opt);
	assert(dummy == NULL);

	/* opt is set from bam_argv[0] and is always non-NULL */
	BAM_DPRINTF(("%s: entered. arg: %s\n", fcn, opt));

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
		bam_error(_("invalid option: %s\n"), opt);
		return (BAM_ERROR);
	}

	/*
	 * kernel and args are allowed without "=new_value" strings.  All
	 * others cause errors
	 */
	if ((val == NULL) && (optnum != KERNEL_CMD) && (optnum != ARGS_CMD)) {
		bam_error(_("option has no argument: %s\n"), opt);
		return (BAM_ERROR);
	} else if (val != NULL) {
		*val = '=';
	}

	if ((optnum == KERNEL_CMD) || (optnum == ARGS_CMD)) {
		BAM_DPRINTF(("%s: setting %s option to %s\n",
		    fcn, menu_cmds[optnum], val ? val + 1 : "NULL"));

		if (val)
			rv = set_kernel(mp, optnum, val + 1, buf, sizeof (buf));
		else
			rv = get_kernel(mp, optnum, buf, sizeof (buf));
		if ((rv == BAM_SUCCESS) && (buf[0] != '\0'))
			(void) printf("%s\n", buf);
	} else {
		optval = s_strtol(val + 1);
		BAM_DPRINTF(("%s: setting %s option to %s\n", fcn,
		    menu_cmds[optnum], val + 1));
		rv = set_global(mp, menu_cmds[optnum], optval);
	}

	if (rv == BAM_WRITE || rv == BAM_SUCCESS) {
		BAM_DPRINTF(("%s: returning SUCCESS\n", fcn));
	} else {
		BAM_DPRINTF(("%s: returning FAILURE\n", fcn));
	}

	return (rv);
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
			bam_error(_("menu file not found: %s\n"), menu_path);
		return (BAM_ERROR);
	}

	done = 0;
	for (lp = mp->start; lp; lp = lp->next) {
		if (lp->flags != BAM_GLOBAL)
			continue;

		if (lp->cmd == NULL) {
			if (!quiet)
				bam_error(_("no command at line %d\n"),
				    lp->lineNum);
			continue;
		}

		if (strcmp(globalcmd, lp->cmd) != 0)
			continue;

		/* Found global. Check for duplicates */
		if (done && !quiet) {
			bam_error(_("duplicate command %s at line %d of "
			    "%sboot/grub/menu.lst\n"), globalcmd,
			    lp->lineNum, bam_root);
			ret = BAM_ERROR;
		}

		arg = lp->arg ? lp->arg : "";
		bam_print(_("%s %s\n"), globalcmd, arg);
		done = 1;
	}

	if (!done && bam_verbose)
		bam_print(_("no %s entry found\n"), globalcmd);

	return (ret);
}

static error_t
menu_write(char *root, menu_t *mp)
{
	const char *fcn = "menu_write()";

	BAM_DPRINTF(("%s: entered menu_write() for root: <%s>\n", fcn, root));
	return (list2file(root, MENU_TMP, GRUB_MENU, mp->start));
}

void
line_free(line_t *lp)
{
	if (lp == NULL)
		return;

	if (lp->cmd != NULL)
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
exec_cmd(char *cmdline, filelist_t *flistp)
{
	char buf[BUFSIZ];
	int ret;
	FILE *ptr;
	sigset_t set;
	void (*disp)(int);

	/*
	 * For security
	 * - only absolute paths are allowed
	 * - set IFS to space and tab
	 */
	if (*cmdline != '/') {
		bam_error(_("path is not absolute: %s\n"), cmdline);
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
		bam_error(_("cannot unblock SIGCHLD: %s\n"), strerror(errno));
		return (-1);
	}

	/*
	 * Set SIGCHLD disposition to SIG_DFL for popen/pclose
	 */
	disp = sigset(SIGCHLD, SIG_DFL);
	if (disp == SIG_ERR) {
		bam_error(_("cannot set SIGCHLD disposition: %s\n"),
		    strerror(errno));
		return (-1);
	}
	if (disp == SIG_HOLD) {
		bam_error(_("SIGCHLD signal blocked. Cannot exec: %s\n"),
		    cmdline);
		return (-1);
	}

	ptr = popen(cmdline, "r");
	if (ptr == NULL) {
		bam_error(_("popen failed: %s: %s\n"), cmdline,
		    strerror(errno));
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
	while (s_fgets(buf, sizeof (buf), ptr) != NULL) {
		if (flistp == NULL) {
			/* s_fgets strips newlines, so insert them at the end */
			bam_print(_("%s\n"), buf);
		} else {
			append_to_flist(flistp, buf);
		}
	}

	ret = pclose(ptr);
	if (ret == -1) {
		bam_error(_("pclose failed: %s: %s\n"), cmdline,
		    strerror(errno));
		return (-1);
	}

	if (WIFEXITED(ret)) {
		return (WEXITSTATUS(ret));
	} else {
		bam_error(_("command terminated abnormally: %s: %d\n"),
		    cmdline, ret);
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
			bam_error(_("the following line is too long "
			    "(> %d chars)\n\t%s\n"), buflen - 1, buf);
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
		bam_error(_("could not allocate memory: size = %u\n"),
		    nelem*sz);
		bam_exit(1);
	}
	return (ptr);
}

void *
s_realloc(void *ptr, size_t sz)
{
	ptr = realloc(ptr, sz);
	if (ptr == NULL) {
		bam_error(_("could not allocate memory: size = %u\n"), sz);
		bam_exit(1);
	}
	return (ptr);
}

char *
s_strdup(char *str)
{
	char *ptr;

	if (str == NULL)
		return (NULL);

	ptr = strdup(str);
	if (ptr == NULL) {
		bam_error(_("could not allocate memory: size = %u\n"),
		    strlen(str) + 1);
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

	if (bam_alt_platform) {
		if (strcmp(bam_platform, "i86pc") == 0) {
			amd64 = 1;		/* diskless server */
		}
	} else {
		if (sysinfo(SI_ISALIST, isabuf, sizeof (isabuf)) > 0 &&
		    strncmp(isabuf, "amd64 ", strlen("amd64 ")) == 0) {
			amd64 = 1;
		} else if (strstr(isabuf, "i386") == NULL) {
			amd64 = 1;		/* diskless server */
		}
	}
	if (amd64 == -1)
		amd64 = 0;

	return (amd64);
}

static char *
get_machine(void)
{
	static int cached = -1;
	static char mbuf[257];	/* from sysinfo(2) manpage */

	if (cached == 0)
		return (mbuf);

	if (bam_alt_platform) {
		return (bam_platform);
	} else {
		if (sysinfo(SI_MACHINE, mbuf, sizeof (mbuf)) > 0) {
			cached = 1;
		}
	}
	if (cached == -1) {
		mbuf[0] = '\0';
		cached = 0;
	}

	return (mbuf);
}

int
is_sparc(void)
{
	static int issparc = -1;
	char mbuf[257];	/* from sysinfo(2) manpage */

	if (issparc != -1)
		return (issparc);

	if (bam_alt_platform) {
		if (strncmp(bam_platform, "sun4", 4) == 0) {
			issparc = 1;
		}
	} else {
		if (sysinfo(SI_ARCHITECTURE, mbuf, sizeof (mbuf)) > 0 &&
		    strcmp(mbuf, "sparc") == 0) {
			issparc = 1;
		}
	}
	if (issparc == -1)
		issparc = 0;

	return (issparc);
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

#if !defined(_OBP)

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

		(void) snprintf(file, PATH_MAX, "%s/%s/%s-ucode.%s",
		    bam_root, UCODE_INSTALL_PATH, ucode_vendors[i].filestr,
		    ucode_vendors[i].extstr);

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
