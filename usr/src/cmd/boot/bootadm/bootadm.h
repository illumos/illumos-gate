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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BOOTADM_H
#define	_BOOTADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif  /* TEXT_DOMAIN */

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
	uint8_t	flags;
} entry_t;

/* For flags value in entry_t */
#define	BAM_ENTRY_BOOTADM	0x01	/* entry created by bootadm */
#define	BAM_ENTRY_LU		0x02	/* entry created by Live Upgrade */
#define	BAM_ENTRY_CHAINLOADER	0x04	/* chainloader entry; do not disturb */
#define	BAM_ENTRY_ROOT		0x08	/* entry has a root line */
#define	BAM_ENTRY_MINIROOT	0x10	/* entry uses the failsafe miniroot */
#define	BAM_ENTRY_DBOOT		0x20	/* Is a dboot entry */
#define	BAM_ENTRY_32BIT		0x40	/* Is a 32-bit entry */
#define	BAM_ENTRY_HV		0x80	/* Is a hypervisor entry */

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
	BAM_SKIP	/* Used by upgrade_menu() */
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
	ARGS_CMD
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

extern int bam_verbose;
extern int bam_force;
extern direct_or_multi_t bam_direct;
extern hv_t bam_is_hv;

extern error_t upgrade_menu(menu_t *, char *, char *);
extern void *s_calloc(size_t, size_t);
extern void *s_realloc(void *, size_t);
extern char *s_fgets(char *buf, int n, FILE *fp);
extern void bam_error(char *format, ...);
extern void bam_print_stderr(char *format, ...);
extern error_t dboot_or_multiboot(const char *);
extern char *get_special(char *);
extern char *os_to_grubdisk(char *, int);
extern void update_line(line_t *);
extern int add_boot_entry(menu_t *, char *, char *, char *, char *, char *);
extern int is_grub(const char *);

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
#define	DIRECT_BOOT_FAILSAFE_KERNEL	"/boot/platform/i86pc/kernel/unix"
#define	DIRECT_BOOT_FAILSAFE_LINE	DIRECT_BOOT_FAILSAFE_KERNEL " -s"
#define	DIRECT_BOOT_KERNEL_ZFS	DIRECT_BOOT_KERNEL " " ZFS_BOOT
#define	DIRECT_BOOT_FAILSAFE_LINE_ZFS	DIRECT_BOOT_FAILSAFE_LINE " " ZFS_BOOT

/* Boot archives */
#define	SUN4U_ARCHIVE		"/platform/sun4u/boot_archive"
#define	SUN4V_ARCHIVE		"/platform/sun4v/boot_archive"
#define	DIRECT_BOOT_ARCHIVE	"/platform/i86pc/$ISADIR/boot_archive"
#define	DIRECT_BOOT_ARCHIVE_32	"/platform/i86pc/boot_archive"
#define	DIRECT_BOOT_ARCHIVE_64	"/platform/i86pc/amd64/boot_archive"
#define	MULTI_BOOT_ARCHIVE	DIRECT_BOOT_ARCHIVE_32
#define	MINIROOT	"/boot/x86.miniroot-safe"

/* Hypervisors */
#define	XEN_32			"/boot/xen.gz"
#define	XEN_64			"/boot/amd64/xen.gz"
#define	XEN_MENU		"/boot/$ISADIR/xen.gz"
#define	HYPERVISOR_KERNEL	"/platform/i86xpv/kernel/$ISADIR/unix"
#define	KERNEL_MODULE_LINE	HYPERVISOR_KERNEL " " HYPERVISOR_KERNEL
#define	KERNEL_MODULE_LINE_ZFS	\
	HYPERVISOR_KERNEL " " HYPERVISOR_KERNEL " " ZFS_BOOT

#ifdef __cplusplus
}
#endif

#endif	/* _BOOTADM_H */
