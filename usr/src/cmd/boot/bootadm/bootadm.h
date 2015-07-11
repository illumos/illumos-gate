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
 *
 * Copyright 2016 Toomas Soome <tsoome@me.com>.
 */

#ifndef _BOOTADM_H
#define	_BOOTADM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <assert.h>
#include <libintl.h>

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif  /* TEXT_DOMAIN */

#ifndef	lint
#define	_(x) gettext(x)
#else
#define	_(x) (x)
#endif

/* Type definitions */

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
	struct line *prev;
} line_t;

typedef struct entry {
	struct entry *next;
	struct entry *prev;
	line_t *start;
	line_t *end;
	int	entryNum;
	uint_t	flags;
} entry_t;

/* For flags value in entry_t */
#define	BAM_ENTRY_BOOTADM	0x01	/* entry created by bootadm */
#define	BAM_ENTRY_LU		0x02	/* entry created by Live Upgrade */
#define	BAM_ENTRY_CHAINLOADER	0x04	/* chainloader entry; do not disturb */
#define	BAM_ENTRY_ROOT		0x08	/* entry has a root line */
#define	BAM_ENTRY_FAILSAFE	0x10	/* failsafe entry  */
#define	BAM_ENTRY_DBOOT		0x20	/* Is dboot (normal or failsafe) */
#define	BAM_ENTRY_32BIT		0x40	/* Is a 32-bit entry */
#define	BAM_ENTRY_HV		0x80	/* Is a hypervisor entry */
#define	BAM_ENTRY_FINDROOT	0x100	/* entry has a findroot line */
#define	BAM_ENTRY_MULTIBOOT	0x200	/* is multiboot (normal or failsafe) */
#define	BAM_ENTRY_64BIT		0x400	/* Is a 64-bit entry */

#define	BAM_ENTRY_UPGFSKERNEL	0x800	/* Upgrade failsafe kernel entry */
#define	BAM_ENTRY_UPGFSMODULE	0x1000  /* Upgrade failsafe module entry */

#define	BAM_ENTRY_LIBBE		0x2000	/* entry created by libbe */

typedef struct {
	line_t	*start;
	line_t	*end;
	line_t	*curdefault;	/* line containing default */
	line_t	*olddefault;	/* old default line (commented) */
	line_t	*old_rc_default;	/* old default line for bootenv.rc */
	entry_t	*entries;	/* os entries */
} menu_t;

typedef enum {
	BAM_ERROR = -1,	/* Must be negative. add_boot_entry() depends on it */
	BAM_SUCCESS = 0,
	BAM_WRITE = 2,
	BAM_MSG,	/* Used by upgrade_menu() */
	BAM_NOCHANGE	/* Used by cvt_to_hyper()/cvt_to_metal() */
} error_t;

/*
 * Menu related
 * menu_cmd_t and menu_cmds must be kept in sync
 *
 * The *_DOLLAR_CMD values must be 1 greater than the
 * respective [KERNEL|MODULE]_CMD values.
 */
typedef enum {
	DEFAULT_CMD = 0,
	TIMEOUT_CMD,
	TITLE_CMD,
	ROOT_CMD,
	KERNEL_CMD,
	KERNEL_DOLLAR_CMD,	/* Must be KERNEL_CMD + 1 */
	MODULE_CMD,
	MODULE_DOLLAR_CMD,	/* Must be MODULE_CMD + 1 */
	SEP_CMD,
	COMMENT_CMD,
	CHAINLOADER_CMD,
	ARGS_CMD,
	FINDROOT_CMD,
	BOOTFS_CMD
} menu_cmd_t;

extern char *menu_cmds[];

/* For multi- or direct-boot */
typedef enum {
	BAM_DIRECT_NOT_SET,
	BAM_DIRECT_MULTIBOOT,
	BAM_DIRECT_DBOOT
} direct_or_multi_t;

/* Is there a hypervisor present? */
typedef enum {
	BAM_HV_UNKNOWN,
	BAM_HV_NO,
	BAM_HV_PRESENT
} hv_t;

/* Is there findroot capability present ? */
typedef enum {
	BAM_FINDROOT_UNKNOWN,
	BAM_FINDROOT_ABSENT,
	BAM_FINDROOT_PRESENT
} findroot_t;

typedef enum {
	OPT_ABSENT = 0,		/* No option */
	OPT_REQ,		/* option required */
	OPT_OPTIONAL		/* option may or may not be present */
} option_t;

typedef struct {
	char	*subcmd;
	option_t option;
	error_t	(*handler)();
	int	unpriv;			/* is this an unprivileged command */
} subcmd_defn_t;

typedef enum zfs_mnted {
	ZFS_MNT_ERROR = -1,
	LEGACY_MOUNTED = 1,
	LEGACY_ALREADY,
	ZFS_MOUNTED,
	ZFS_ALREADY
} zfs_mnted_t;

extern int bam_verbose;
extern int bam_force;
extern direct_or_multi_t bam_direct;
extern hv_t bam_is_hv;
extern findroot_t bam_is_findroot;
extern int bam_debug;

extern void bam_add_line(menu_t *mp, entry_t *entry, line_t *prev, line_t *lp);
extern void update_numbering(menu_t *mp);
extern error_t set_global(menu_t *, char *, int);
extern error_t upgrade_menu(menu_t *, char *, char *);
extern error_t cvt_to_hyper(menu_t *, char *, char *);
extern error_t cvt_to_metal(menu_t *, char *, char *);
extern error_t check_subcmd_and_options(char *, char *, subcmd_defn_t *,
    error_t (**fp)());
extern char *mount_top_dataset(char *pool, zfs_mnted_t *mnted);
extern void elide_trailing_slash(const char *, char *, size_t);
extern int umount_top_dataset(char *, zfs_mnted_t, char *);
extern void *s_calloc(size_t, size_t);
extern void *s_realloc(void *, size_t);
extern char *s_fgets(char *buf, int n, FILE *fp);
extern void bam_error(char *format, ...);
extern void bam_exit(int);
extern void bam_print(char *, ...);
extern void bam_print_stderr(char *format, ...);
extern void bam_derror(char *format, ...);
extern error_t bam_loader_menu(char *, char *, int, char *[]);
extern error_t get_boot_cap(const char *osroot);
extern char *get_special(char *);
extern char *os_to_grubdisk(char *, int);
extern void update_line(line_t *);
extern int add_boot_entry(menu_t *, char *, char *, char *, char *, char *,
    char *);
extern error_t delete_boot_entry(menu_t *, int, int);
extern int is_grub(const char *);
extern char *get_grubsign(char *osroot, char *osdev);
extern char *get_grubroot(char *osroot, char *osdev, char *menu_root);
extern int root_optional(char *osroot, char *menu_root);
extern void unlink_line(menu_t *mp, line_t *lp);
extern void line_free(line_t *lp);
extern char *s_strdup(char *);
extern int is_sparc(void);
extern int is_pcfs(char *);
extern int is_zfs(char *);
extern int bootadm_digest(const char *, char **);

#define	BAM_MAXLINE	8192

/* menu.lst comments created by bootadm */
#define	BAM_BOOTADM_HDR	"---------- ADDED BY BOOTADM - DO NOT EDIT ----------"
#define	BAM_BOOTADM_FTR	"---------------------END BOOTADM--------------------"

/*
 * menu.lst comments create by Live Upgrade.  Note that these are the end of
 * the comment strings - there will be other text before them.
 */
#define	BAM_LU_HDR	" - ADDED BY LIVE UPGRADE - DO NOT EDIT  -----"
#define	BAM_LU_FTR	" -------------- END LIVE UPGRADE ------------"

#define	BAM_OLDDEF	"BOOTADM SAVED DEFAULT: "
#define	BAM_OLD_RC_DEF	"BOOTADM RC SAVED DEFAULT: "

/*
 * menu.lst comment created by libbe
 */
#define	BAM_LIBBE_FTR	"============ End of LIBBE entry ============="

/* Title used for failsafe entries */
#define	FAILSAFE_TITLE	"Solaris failsafe"

/* Title used for hv entries */
#define	NEW_HV_ENTRY	"Solaris xVM"

/* ZFS boot option */
#define	ZFS_BOOT	"-B $ZFS-BOOTFS"

/* multiboot */
#define	MULTI_BOOT	"/platform/i86pc/multiboot"
#define	MULTI_BOOT_FAILSAFE	"/boot/multiboot"
#define	MULTI_BOOT_FAILSAFE_UNIX	"kernel/unix"
#define	MULTI_BOOT_FAILSAFE_LINE	"/boot/multiboot kernel/unix -s"

/* directboot kernels */
#define	DIRECT_BOOT_32	"/platform/i86pc/kernel/unix"
#define	DIRECT_BOOT_64	"/platform/i86pc/kernel/amd64/unix"
#define	DIRECT_BOOT_KERNEL	"/platform/i86pc/kernel/$ISADIR/unix"
#define	DIRECT_BOOT_FAILSAFE_32	"/boot/platform/i86pc/kernel/unix"
#define	DIRECT_BOOT_FAILSAFE_64	"/boot/platform/i86pc/kernel/amd64/unix"
#define	DIRECT_BOOT_FAILSAFE_KERNEL \
	"/boot/platform/i86pc/kernel/$ISADIR/unix"
#define	DIRECT_BOOT_FAILSAFE_LINE	DIRECT_BOOT_FAILSAFE_KERNEL " -s"
#define	DIRECT_BOOT_KERNEL_ZFS	DIRECT_BOOT_KERNEL " " ZFS_BOOT
#define	DIRECT_BOOT_PREFIX	"/platform/i86pc/"
#define	KERNEL_PREFIX	"/platform/i86pc/"
#define	AMD_UNIX_SPACE	"/amd64/unix "
#define	UNIX_SPACE	"/unix "

/* xVM kernels */
#define	XEN_KERNEL_SUBSTR "xen.gz"

/* Boot archives */
#define	ARCHIVE_PREFIX		"/platform/"
#define	ARCHIVE_SUFFIX		"/boot_archive"
#define	CACHEDIR_SUFFIX		"/archive_cache"
#define	UPDATEDIR_SUFFIX	"/updates"
#define	DIRECT_BOOT_ARCHIVE	"/platform/i86pc/$ISADIR/boot_archive"
#define	DIRECT_BOOT_ARCHIVE_32	"/platform/i86pc/boot_archive"
#define	DIRECT_BOOT_ARCHIVE_64	"/platform/i86pc/amd64/boot_archive"
#define	MULTIBOOT_ARCHIVE	DIRECT_BOOT_ARCHIVE_32
#define	FAILSAFE_ARCHIVE	"/boot/$ISADIR/x86.miniroot-safe"
#define	FAILSAFE_ARCHIVE_32	"/boot/x86.miniroot-safe"
#define	FAILSAFE_ARCHIVE_64	"/boot/amd64/x86.miniroot-safe"
#define	CACHEDIR_32		"/platform/i86pc/archive_cache"
#define	CACHEDIR_64		"/platform/i86pc/amd64/archive_cache"
#define	UPDATEDIR_32		"/platform/i86pc/updates"
#define	UPDATEDIR_64		"/platform/i86pc/amd64/updates"

/* Hypervisors */
#define	XEN_64			"/boot/amd64/xen.gz"
#define	XEN_MENU		"/boot/$ISADIR/xen.gz"
#define	HYPERVISOR_KERNEL	"/platform/i86xpv/kernel/$ISADIR/unix"
#define	XEN_KERNEL_MODULE_LINE	HYPERVISOR_KERNEL " " HYPERVISOR_KERNEL
#define	XEN_KERNEL_MODULE_LINE_ZFS	\
	HYPERVISOR_KERNEL " " HYPERVISOR_KERNEL " " ZFS_BOOT

/* Helpers */
#define	MKISOFS_PATH		"/usr/bin/mkisofs"
#define	DD_PATH_USR		"/usr/bin/dd"
#define	LOCKFS_PATH		"/usr/sbin/lockfs"

/* A first guess at the number of entries in a menu */
#define	BAM_ENTRY_NUM		10

/* toggle for whether delete_boot_entry prints an error message or not */
#define	DBE_PRINTERR		0
#define	DBE_QUIET		1

/*
 * Debugging defines
 */
#define	INJECT_ERROR1(x, y)	\
{ \
	if (bam_debug) { \
		char *inj = getenv("_BOOTADM_INJECT"); \
		if (inj && strcmp(inj, (x)) == 0) {  \
			y;	\
		} \
	} \
}

#define	INJECT_ERROR2(x, y, z)	\
{ \
	if (bam_debug) { \
		char *inj = getenv("_BOOTADM_INJECT"); \
		if (inj && strcmp(inj, (x)) == 0) {  \
			y;	\
			z;	\
		} \
	} \
}

#define	BAM_DPRINTF(x)	{if (bam_debug)  bam_derror x; }

#ifdef __cplusplus
}
#endif

#endif	/* _BOOTADM_H */
