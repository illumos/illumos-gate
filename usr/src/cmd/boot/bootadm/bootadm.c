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
#include <sys/systeminfo.h>
#include <sys/dktp/fdisk.h>

#include <pwd.h>
#include <grp.h>
#include <device_info.h>

#include <libintl.h>
#include <locale.h>

#include <assert.h>

#include "message.h"

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif	/* TEXT_DOMAIN */

/* Type definitions */

/* Primary subcmds */
typedef enum {
	BAM_MENU = 3,
	BAM_ARCHIVE
} subcmd_t;

/* GRUB menu per-line classification */
typedef enum {
	BAM_INVALID = 0,
	BAM_EMPTY,
	BAM_COMMENT,
	BAM_GLOBAL,
	BAM_ENTRY,
	BAM_TITLE
} menu_flag_t;

/* struct for menu.lst contents */
typedef struct line {
	int  lineNum;	/* Line number in menu.lst */
	int  entryNum;	/* menu boot entry #. ENTRY_INIT if not applicable */
	char *cmd;
	char *sep;
	char *arg;
	char *line;
	menu_flag_t flags;
	struct line *next;
} line_t;

typedef struct {
	line_t *start;
	line_t *end;
} menu_t;

typedef enum {
    OPT_ABSENT = 0,	/* No option */
    OPT_REQ,		/* option required */
    OPT_OPTIONAL	/* option may or may not be present */
} option_t;

typedef enum {
    BAM_ERROR = -1,
    BAM_SUCCESS = 0,
    BAM_WRITE = 2
} error_t;

typedef struct {
	char	*subcmd;
	option_t option;
	error_t (*handler)();
} subcmd_defn_t;


#define	BAM_MAXLINE	8192

#define	LINE_INIT	0	/* lineNum initial value */
#define	ENTRY_INIT	-1	/* entryNum initial value */
#define	ALL_ENTRIES	-2	/* selects all boot entries */

#define	GRUB_DIR		"/boot/grub"
#define	MULTI_BOOT		"/platform/i86pc/multiboot"
#define	BOOT_ARCHIVE		"/platform/i86pc/boot_archive"
#define	GRUB_MENU		"/boot/grub/menu.lst"
#define	MENU_TMP		"/boot/grub/menu.lst.tmp"
#define	RAMDISK_SPECIAL		"/ramdisk"

/* lock related */
#define	BAM_LOCK_FILE		"/var/run/bootadm.lock"
#define	LOCK_FILE_PERMS		(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#define	CREATE_RAMDISK		"/boot/solaris/bin/create_ramdisk"
#define	CREATE_DISKMAP		"/boot/solaris/bin/create_diskmap"
#define	GRUBDISK_MAP		"/var/run/solaris_grubdisk.map"

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
typedef enum {
	DEFAULT_CMD = 0,
	TIMEOUT_CMD,
	TITLE_CMD,
	ROOT_CMD,
	KERNEL_CMD,
	MODULE_CMD,
	SEP_CMD,
	COMMENT_CMD
} menu_cmd_t;

static char *menu_cmds[] = {
	"default",	/* DEFAULT_CMD */
	"timeout",	/* TIMEOUT_CMD */
	"title",	/* TITLE_CMD */
	"root",		/* ROOT_CMD */
	"kernel",	/* KERNEL_CMD */
	"module",	/* MODULE_CMD */
	" ",		/* SEP_CMD */
	"#",		/* COMMENT_CMD */
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

#define	BAM_HDR		"---------- ADDED BY BOOTADM - DO NOT EDIT ----------"
#define	BAM_FTR		"---------------------END BOOTADM--------------------"


/* Globals */
static char *prog;
static subcmd_t bam_cmd;
static char *bam_root;
static int bam_rootlen;
static int bam_root_readonly;
static char *bam_subcmd;
static char *bam_opt;
static int bam_debug;
static char **bam_argv;
static int bam_argc;
static int bam_force;
static int bam_verbose;
static int bam_check;
static int bam_smf_check;
static int bam_lock_fd = -1;
static char rootbuf[PATH_MAX] = "/";

/* function prototypes */
static void parse_args_internal(int argc, char *argv[]);
static void parse_args(int argc, char *argv[]);
static error_t bam_menu(char *subcmd, char *opt, int argc, char *argv[]);
static error_t bam_archive(char *subcmd, char *opt);

static void bam_error(char *format, ...);
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
static error_t delete_entry(menu_t *mp, char *menu_path, char *opt);
static error_t delete_all_entries(menu_t *mp, char *menu_path, char *opt);
static error_t update_entry(menu_t *mp, char *root, char *opt);
static error_t update_temp(menu_t *mp, char *root, char *opt);

static error_t update_archive(char *root, char *opt);
static error_t list_archive(char *root, char *opt);
static error_t update_all(char *root, char *opt);
static error_t read_list(char *root, filelist_t  *flistp);
static error_t set_global(menu_t *mp, char *globalcmd, int val);
static error_t set_option(menu_t *mp, char *globalcmd, char *opt);

static long s_strtol(char *str);
static char *s_fgets(char *buf, int n, FILE *fp);
static int s_fputs(char *str, FILE *fp);

static void *s_calloc(size_t nelem, size_t sz);
static char *s_strdup(char *str);
static int is_readonly(char *);
static int is_amd64(void);
static void append_to_flist(filelist_t *, char *);

#if defined(__sparc)
static void sparc_abort(void);
#endif

/* Menu related sub commands */
static subcmd_defn_t menu_subcmds[] = {
	"set_option",		OPT_OPTIONAL,	set_option,	/* PUB */
	"list_entry",		OPT_OPTIONAL,	list_entry,	/* PUB */
	"delete_all_entries",	OPT_ABSENT,	delete_all_entries, /* PVT */
	"update_entry",		OPT_REQ,	update_entry,	/* menu */
	"update_temp",		OPT_OPTIONAL,	update_temp,	/* reboot */
	NULL,			0,		NULL	/* must be last */
};

/* Archive related sub commands */
static subcmd_defn_t arch_subcmds[] = {
	"update",		OPT_ABSENT,	update_archive, /* PUB */
	"update_all",		OPT_ABSENT,	update_all,	/* PVT */
	"list",			OPT_OPTIONAL,	list_archive,	/* PUB */
	NULL,			0,		NULL	/* must be last */
};

static struct {
	nvlist_t *new_nvlp;
	nvlist_t *old_nvlp;
	int need_update;
} walk_arg;

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

	if (geteuid() != 0) {
		bam_error(MUST_BE_ROOT);
		bam_exit(1);
	}

	bam_lock();

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
	while ((c = getopt(argc, argv, "a:d:fm:no:vR:")) != -1) {
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
			bam_smf_check = bam_root_readonly;
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
			bam_root = rootbuf;
			if (rootbuf[strlen(rootbuf) - 1] != '/')
				(void) strcat(rootbuf, "/");
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

static error_t
bam_menu(char *subcmd, char *opt, int largc, char *largv[])
{
	error_t ret;
	char menu_path[PATH_MAX];
	menu_t *menu;
	error_t (*f)(menu_t *mp, char *menu_path, char *opt);

	/*
	 * Check arguments
	 */
	ret = check_subcmd_and_options(subcmd, opt, menu_subcmds, &f);
	if (ret == BAM_ERROR) {
		return (BAM_ERROR);
	}

	(void) snprintf(menu_path, sizeof (menu_path), "%s%s",
	    bam_root, GRUB_MENU);

	menu = menu_read(menu_path);
	assert(menu);

	/*
	 * Special handling for setting timeout and default
	 */
	if (strcmp(subcmd, "set_option") == 0) {
		if (largc != 1 || largv[0] == NULL) {
			usage();
			return (BAM_ERROR);
		}
		opt = largv[0];
	} else if (largc != 0) {
		usage();
		return (BAM_ERROR);
	}

	/*
	 * Once the sub-cmd handler has run
	 * only the line field is guaranteed to have valid values
	 */
	if (strcmp(subcmd, "update_entry") == 0)
		ret = f(menu, bam_root, opt);
	else
		ret = f(menu, menu_path, opt);
	if (ret == BAM_WRITE) {
		ret = menu_write(bam_root, menu);
	}

	menu_free(menu);

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

	/*
	 * Check archive not supported with update_all
	 * since it is awkward to display out-of-sync
	 * information for each BE.
	 */
	if (bam_check && strcmp(subcmd, "update_all") == 0) {
		bam_error(CHECK_NOT_SUPPORTED, subcmd);
		return (BAM_ERROR);
	}

	return (f(bam_root, opt));
}

/*PRINTFLIKE1*/
static void
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
	 * If we are invoked as part of system/filesyste/boot-archive
	 * SMF service, ignore amd64 modules unless we are booted amd64.
	 */
	if (bam_smf_check && !is_amd64() && strstr(file, "/amd64/") == 0)
		return (0);

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
	(void) snprintf(path, sizeof (path), "%s%s", root, BOOT_ARCHIVE);
	if (stat(path, &sb) != 0) {
		if (bam_verbose && !bam_check)
			bam_print(UPDATE_ARCH_MISS, path);
		walk_arg.need_update = 1;
		return;
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
	(void) snprintf(path, sizeof (path), "%s%s", root, BOOT_ARCHIVE);
	if (stat(path, &sb) != 0) {
		bam_error(ARCHIVE_NOT_CREATED, path);
		return (BAM_ERROR);
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

	/*
	 * There are 3 situations where creating archive is
	 * of dubious value:
	 *	- create boot_archive on a boot_archive
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

	found = 0;
	while (getextmntent(fp, &mnt, sizeof (mnt)) == 0) {
		if (strcmp(mnt.mnt_mountp, root) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		if (bam_verbose)
			bam_error(NOT_IN_MNTTAB, root);
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
	 * root must belong to a newboot OS,
	 * don't care on sparc except for diskless clients
	 */
	if (!is_newboot(root)) {
		if (bam_verbose)
			bam_print(NOT_NEWBOOT);
		return (BAM_SUCCESS);
	}

	/*
	 * root must be writable
	 * Note: statvfs() does not always report the truth
	 */
	if (is_readonly(root)) {
		if (!bam_smf_check && bam_verbose)
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

static error_t
update_all(char *root, char *opt)
{
	struct extmnttab mnt;
	struct stat sb;
	FILE *fp;
	char multibt[PATH_MAX];
	error_t ret = BAM_SUCCESS;

	assert(bam_rootlen == 1 && root[0] == '/');
	assert(opt == NULL);

	/*
	 * First update archive for current root
	 */
	if (update_archive(root, opt) != BAM_SUCCESS)
		ret = BAM_ERROR;

	/*
	 * Now walk the mount table, performing archive update
	 * for all mounted Newboot root filesystems
	 */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		bam_error(OPEN_FAIL, MNTTAB, strerror(errno));
		return (BAM_ERROR);
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
		if (update_archive(rootbuf, opt) != BAM_SUCCESS)
			ret = BAM_ERROR;
	}

	(void) fclose(fp);

	return (ret);
}

static void
append_line(menu_t *mp, line_t *lp)
{
	if (mp->start == NULL) {
		mp->start = lp;
	} else {
		mp->end->next = lp;
	}
	mp->end = lp;
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
	static line_t *prev;

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
		    prev->arg && strcmp(prev->arg, BAM_HDR) == 0)
			prev->entryNum = lp->entryNum;
	} else if (flag != BAM_INVALID) {
		/*
		 * For header comments, the entry# is "fixed up"
		 * by the subsequent title
		 */
		lp->entryNum = *entryNum;
		lp->flags = flag;
	} else {
		lp->entryNum = *entryNum;
		lp->flags = (*entryNum == ENTRY_INIT) ? BAM_GLOBAL : BAM_ENTRY;
	}

	append_line(mp, lp);

	prev = lp;
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

static int
add_boot_entry(menu_t *mp,
	char *title,
	char *root,
	char *kernel,
	char *module)
{
	menu_t dummy;
	int lineNum, entryNum;
	char linebuf[BAM_MAXLINE];

	assert(mp);

	if (title == NULL) {
		bam_error(SUBOPT_MISS, menu_cmds[TITLE_CMD]);
		return (BAM_ERROR);
	}
	if (root == NULL) {
		bam_error(SUBOPT_MISS, menu_cmds[ROOT_CMD]);
		return (BAM_ERROR);
	}
	if (kernel == NULL) {
		bam_error(SUBOPT_MISS, menu_cmds[KERNEL_CMD]);
		return (BAM_ERROR);
	}
	if (module == NULL) {
		bam_error(SUBOPT_MISS, menu_cmds[MODULE_CMD]);
		return (BAM_ERROR);
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
	    menu_cmds[COMMENT_CMD], BAM_HDR);
	dummy.start = dummy.end = NULL;
	line_parser(&dummy, linebuf, &lineNum, &entryNum);
	if (dummy.start == NULL || dummy.start->flags != BAM_COMMENT) {
		line_free(dummy.start);
		bam_error(INVALID_HDR, BAM_HDR);
		return (BAM_ERROR);
	}
	assert(dummy.start == dummy.end);
	append_line(mp, dummy.start);

	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[TITLE_CMD], menu_cmds[SEP_CMD], title);
	dummy.start = dummy.end = NULL;
	line_parser(&dummy, linebuf, &lineNum, &entryNum);
	if (dummy.start == NULL || dummy.start->flags != BAM_TITLE) {
		line_free(dummy.start);
		bam_error(INVALID_TITLE, title);
		return (BAM_ERROR);
	}
	assert(dummy.start == dummy.end);
	append_line(mp, dummy.start);


	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[ROOT_CMD], menu_cmds[SEP_CMD], root);
	dummy.start = dummy.end = NULL;
	line_parser(&dummy, linebuf, &lineNum, &entryNum);
	if (dummy.start == NULL || dummy.start->flags != BAM_ENTRY) {
		line_free(dummy.start);
		bam_error(INVALID_ROOT, root);
		return (BAM_ERROR);
	}
	assert(dummy.start == dummy.end);
	append_line(mp, dummy.start);


	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[KERNEL_CMD], menu_cmds[SEP_CMD], kernel);
	dummy.start = dummy.end = NULL;
	line_parser(&dummy, linebuf, &lineNum, &entryNum);
	if (dummy.start == NULL || dummy.start->flags != BAM_ENTRY) {
		line_free(dummy.start);
		bam_error(INVALID_KERNEL, kernel);
		return (BAM_ERROR);
	}
	assert(dummy.start == dummy.end);
	append_line(mp, dummy.start);

	(void) snprintf(linebuf, sizeof (linebuf), "%s%s%s",
	    menu_cmds[MODULE_CMD], menu_cmds[SEP_CMD], module);
	dummy.start = dummy.end = NULL;
	line_parser(&dummy, linebuf, &lineNum, &entryNum);
	if (dummy.start == NULL || dummy.start->flags != BAM_ENTRY) {
		line_free(dummy.start);
		bam_error(INVALID_MODULE, module);
		return (BAM_ERROR);
	}
	assert(dummy.start == dummy.end);
	append_line(mp, dummy.start);

	(void) snprintf(linebuf, sizeof (linebuf), "%s%s",
	    menu_cmds[COMMENT_CMD], BAM_FTR);
	dummy.start = dummy.end = NULL;
	line_parser(&dummy, linebuf, &lineNum, &entryNum);
	if (dummy.start == NULL || dummy.start->flags != BAM_COMMENT) {
		line_free(dummy.start);
		bam_error(INVALID_FOOTER, BAM_FTR);
		return (BAM_ERROR);
	}
	assert(dummy.start == dummy.end);
	append_line(mp, dummy.start);

	return (entryNum);
}

static error_t
do_delete(menu_t *mp, int entryNum)
{
	int bootadm_entry = 0;
	line_t *lp, *prev, *save;
	int deleted;

	assert(entryNum != ENTRY_INIT);

	deleted = 0;
	prev = NULL;
	for (lp = mp->start; lp; ) {

		if (lp->entryNum == ENTRY_INIT) {
			prev = lp;
			lp = lp->next;
			continue;
		}

		if (entryNum != ALL_ENTRIES && lp->entryNum != entryNum) {
			prev = lp;
			lp = lp->next;
			continue;
		}

		/*
		 * can only delete bootadm entries
		 */
		if (lp->flags == BAM_COMMENT && strcmp(lp->arg, BAM_HDR) == 0) {
			bootadm_entry = 1;
		}

		if (!bootadm_entry) {
			prev = lp;
			lp = lp->next;
			continue;
		}

		if (lp->flags == BAM_COMMENT && strcmp(lp->arg, BAM_FTR) == 0)
			bootadm_entry = 0;

		if (prev == NULL)
			mp->start = lp->next;
		else
			prev->next = lp->next;
		if (mp->end == lp)
			mp->end = prev;
		save = lp->next;
		line_free(lp);
		lp = save;	/* prev stays the same */

		deleted = 1;
	}

	if (!deleted && entryNum != ALL_ENTRIES) {
		bam_error(NO_BOOTADM_MATCH);
		return (BAM_ERROR);
	}

	return (BAM_SUCCESS);
}

static error_t
delete_entry(menu_t *mp, char *menu_path, char *opt)
{
	int entry = ENTRY_INIT;
	char *title = NULL;
	line_t *lp;

	assert(mp);
	assert(opt);

	/*
	 * Do a quick check. If the file is empty
	 * we have nothing to delete
	 */
	if (mp->start == NULL) {
		bam_print(EMPTY_FILE, menu_path);
		return (BAM_SUCCESS);
	}

	if (selector(mp, opt, &entry, &title) != BAM_SUCCESS) {
		return (BAM_ERROR);
	}
	assert((entry != ENTRY_INIT) ^ (title != NULL));

	for (lp = mp->start; lp; lp = lp->next) {
		if (entry != ENTRY_INIT)
			break;
		assert(title);
		if (lp->flags == BAM_TITLE &&
		    lp->arg && strcmp(lp->arg, title) == 0) {
			entry = lp->entryNum;
			break;
		}
	}

	if (entry == ENTRY_INIT) {
		bam_error(NO_MATCH, title);
		return (BAM_ERROR);
	}

	if (do_delete(mp, entry) != BAM_SUCCESS) {
		return (BAM_ERROR);
	}

	return (BAM_WRITE);
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
open_diskmap(void)
{
	FILE *fp;
	char cmd[PATH_MAX];

	/* make sure we have a map file */
	fp = fopen(GRUBDISK_MAP, "r");
	if (fp == NULL) {
		(void) snprintf(cmd, sizeof (cmd),
		    "%s > /dev/null", CREATE_DISKMAP);
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

static char *get_title(char *rootdir)
{
	static char title[80];	/* from /etc/release */
	char *cp, release[PATH_MAX];
	FILE *fp;

	/* open the /etc/release file */
	(void) snprintf(release, sizeof (release), "%s/etc/release", rootdir);

	fp = fopen(release, "r");
	if (fp == NULL)
		return ("Solaris");	/* default to Solaris */

	while (s_fgets(title, sizeof (title), fp) != NULL) {
		cp = strstr(title, "Solaris");
		if (cp)
			break;
	}
	(void) fclose(fp);
	return (cp);
}

static char *
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

static char *
os_to_grubdisk(char *osdisk, int on_bootdev)
{
	FILE *fp;
	char *grubdisk;

	/* translate /dev/dsk name to grub disk name */
	fp = open_diskmap();
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

/*ARGSUSED*/
static error_t
update_entry(menu_t *mp, char *menu_root, char *opt)
{
	FILE *fp;
	int entry;
	line_t *lp;
	char *grubdisk, *title, *osdev, *osroot;
	int bootadm_entry, entry_to_delete;

	assert(mp);
	assert(opt);

	osdev = strtok(opt, ",");
	osroot = strtok(NULL, ",");
	if (osroot == NULL)
		osroot = menu_root;
	title = get_title(osroot);

	/* translate /dev/dsk name to grub disk name */
	fp = open_diskmap();
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

	/* delete existing entries with matching grub hd name */
	for (;;) {
		entry_to_delete = -1;
		bootadm_entry = 0;
		for (lp = mp->start; lp; lp = lp->next) {
			/*
			 * can only delete bootadm entries
			 */
			if (lp->flags == BAM_COMMENT) {
				if (strcmp(lp->arg, BAM_HDR) == 0)
					bootadm_entry = 1;
				else if (strcmp(lp->arg, BAM_FTR) == 0)
					bootadm_entry = 0;
			}

			if (bootadm_entry && lp->flags == BAM_ENTRY &&
			    strcmp(lp->cmd, menu_cmds[ROOT_CMD]) == 0 &&
			    strcmp(lp->arg, grubdisk) == 0) {
				entry_to_delete = lp->entryNum;
			}
		}
		if (entry_to_delete == -1)
			break;
		(void) do_delete(mp, entry_to_delete);
	}

	/* add the entry for normal Solaris */
	entry = add_boot_entry(mp, title, grubdisk,
	    "/platform/i86pc/multiboot",
	    "/platform/i86pc/boot_archive");

	/* add the entry for failsafe archive */
	(void) add_boot_entry(mp, "Solaris failsafe", grubdisk,
	    "/boot/multiboot kernel/unix -s",
	    "/boot/x86.miniroot-safe");
	free(grubdisk);

	if (entry == BAM_ERROR) {
		return (BAM_ERROR);
	}
	(void) set_global(mp, menu_cmds[DEFAULT_CMD], entry);
	return (BAM_WRITE);
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

static error_t
update_temp(menu_t *mp, char *menupath, char *opt)
{
	int entry;
	char *grubdisk, *rootdev;
	char kernbuf[1024];

	assert(mp);

	if (opt != NULL &&
	    strncmp(opt, "entry=", strlen("entry=")) == 0 &&
	    selector(mp, opt, &entry, NULL) == BAM_SUCCESS) {
		/* this is entry=# option */
		return (set_global(mp, menu_cmds[DEFAULT_CMD], entry));
	}

	/* If no option, delete exiting reboot menu entry */
	if (opt == NULL)
		return (delete_entry(mp, menupath, "title="REBOOT_TITLE));

	/*
	 * add a new menu entry base on opt and make it the default
	 * 1. First get root disk name from mnttab
	 * 2. Translate disk name to grub name
	 * 3. Add the new menu entry
	 */
	rootdev = get_special("/");
	if (rootdev) {
		grubdisk = os_to_grubdisk(rootdev, 1);
		free(rootdev);
	}
	if (grubdisk == NULL) {
		return (BAM_ERROR);
	}

	/* add an entry for Solaris reboot */
	(void) snprintf(kernbuf, sizeof (kernbuf),
	    "/platform/i86pc/multiboot %s", opt);
	entry = add_boot_entry(mp, REBOOT_TITLE, grubdisk, kernbuf,
	    "/platform/i86pc/boot_archive");
	free(grubdisk);

	if (entry == BAM_ERROR) {
		return (BAM_ERROR);
	}
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

/*ARGSUSED*/
static error_t
set_option(menu_t *mp, char *menu_path, char *opt)
{
	int optnum, optval;
	char *val;

	assert(mp);
	assert(opt);

	val = strchr(opt, '=');
	if (val == NULL) {
		bam_error(INVALID_ENTRY, opt);
		return (BAM_ERROR);
	}

	*val = '\0';
	if (strcmp(opt, "default") == 0) {
		optnum = DEFAULT_CMD;
	} else if (strcmp(opt, "timeout") == 0) {
		optnum = TIMEOUT_CMD;
	} else {
		bam_error(INVALID_ENTRY, opt);
		return (BAM_ERROR);
	}

	optval = s_strtol(val + 1);
	*val = '=';
	return (set_global(mp, menu_cmds[optnum], optval));
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
	assert(mp);

	if (mp->start)
		linelist_free(mp->start);
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
static char *
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

static void *
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
