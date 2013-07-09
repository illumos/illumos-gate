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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_GRBMIMPL_H
#define	_GRBMIMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mntent.h>
#include <sys/uadmin.h>
#include <sys/dktp/fdisk.h>
#include <libzfs.h>
#include <libdevinfo.h>
#include "libgrubmgmt.h"
#include "libgrub_errno.h"

/*
 * Macros for processing the GRUB menu.
 */
#define	GRUB_MENU	"/boot/grub/menu.lst"
#define	BOOTSIGN_DIR	"/boot/grub/bootsign"
#define	BOOTSIGN_LEN	(2 * MAXNAMELEN)
#define	ZFS_BOOT_VAR	"$ZFS-BOOTFS"	/* ZFS boot option */
#define	ISADIR_VAR	"$ISADIR"	/* ISADIR option */

#define	PRTNUM_INVALID	-1	/* Partition number invlaid */
#define	SLCNUM_INVALID	-1	/* Slice number invalid */

#define	SLCNUM_FIRST		'a'
#define	SLCNUM_WHOLE_DISK	'q'

#define	IS_SLCNUM_VALID(x)	((x) >= SLCNUM_FIRST && (x) < SLCNUM_WHOLE_DISK)
#define	IS_PRTNUM_VALID(x)	((uint_t)(x) < FD_NUMPART + MAX_EXT_PARTS)

#define	GRBM_VALID_FLAG		((uint_t)1 << 31)
#define	GRBM_MAXLINE		8192
#define	IS_ENTRY_VALID(ent)	((ent) && ((ent)->ge_flags & GRBM_VALID_FLAG))
#define	IS_BARG_VALID(barg)	((barg)->gb_flags & GRBM_VALID_FLAG)
#define	IS_ENTRY_BARG_VALID(ent) \
	(IS_ENTRY_VALID(ent) && IS_BARG_VALID(&(ent)->ge_barg))
#define	IS_LINE2BIG(buf, bfsz, len) \
	((len = strlen(buf)) == (bfsz) - 1 && (buf)[len - 1] != '\n')
#define	IS_STR_NULL(x)	((x) == NULL ? "NULL" : (x))
#define	GRUB_ENTRY_IS_XVM(fbarg) \
	(strstr(fbarg.gba_kernel, "xen.gz") != NULL)

enum {
#define	menu_cmd(cmd, num, flags, parsef)	num,
#define	menu_cmd_end(num)			num
#include "libgrub_cmd.def"
};

typedef struct _grub_fs {
	di_node_t		gf_diroot;
	di_devlink_handle_t	gf_dvlh;
	libzfs_handle_t		*gf_lzfh;
} grub_fs_t;


typedef struct _grub_cmd_desc {
	const char	*gcd_cmd;
	uint_t		gcd_num;
	int		gcd_flags;
} grub_cmd_desc_t;


enum {
	GRBM_UFS = 0,
	GRBM_ZFS_TOPFS = 0,
	GRBM_FS_TOP = 0,
	GRBM_ZFS_BOOTFS,
	GRBM_FS_MAX
};

typedef struct _grub_root {
	char		gr_fstyp[MNTMAXSTR];
	char		gr_physpath[MAXPATHLEN];
	grub_fsdesc_t	gr_fs[GRBM_FS_MAX];
} grub_root_t;

/*
 * Data struct for the boot argument constructed from a GRUB menu entry
 */
typedef struct _grub_barg {
	grub_entry_t	*gb_entry;
	grub_line_t	*gb_errline;
	int		gb_walkret;	/* set to 0 when match found */
	uint_t		gb_flags;
	uint_t		gb_prtnum;
	uint_t		gb_slcnum;
	grub_root_t	gb_root;
	char		gb_bootsign[BOOTSIGN_LEN];
	char		gb_kernel[BOOTARGS_MAX];
	char		gb_module[BOOTARGS_MAX];
} grub_barg_t;


/* GRUB menu per-line classification */
enum {
	GRUB_LINE_INVALID = 0,
	GRUB_LINE_EMPTY,
	GRUB_LINE_COMMENT,
	GRUB_LINE_GLOBAL,
	GRUB_LINE_ENTRY,
	GRUB_LINE_TITLE
};

/*
 * Data structures for menu.lst contents
 */
struct grub_line {
	grub_line_t	*gl_next;
	grub_line_t	*gl_prev;
	int		gl_line_num;	/* Line number in menu.lst */
	int		gl_entry_num;	/* menu boot entry #. */
					/* GRUB_ENTRY_DEFAULT if none */
	int		gl_flags;
	uint_t		gl_cmdtp;	/* recognized command type */
	char		*gl_cmd;
	char		*gl_sep;
	char		*gl_arg;
	char		*gl_line;
};

struct grub_entry {
	grub_menu_t	*ge_menu;	/* grub_menu_t it belongs to */
	grub_entry_t	*ge_next;
	grub_entry_t	*ge_prev;
	grub_line_t	*ge_start;
	grub_line_t	*ge_end;
	int		ge_entry_num;
	uint_t		ge_flags;
	uint_t		ge_emask;	/* invalid lines mask */
	grub_barg_t	ge_barg;
};

struct grub_menu {
	grub_line_t	*gm_start;
	grub_line_t	*gm_end;
	grub_line_t	*gm_curdefault;	/* line containing default */
	grub_entry_t	*gm_ent_start;	/* os entries */
	grub_entry_t	*gm_ent_end;
	grub_entry_t	*gm_ent_default;	/* default entry */
	uint_t		gm_line_num;	/* number of lines processed */
	uint_t		gm_entry_num;	/* number of entries processed */
	char		gm_path[MAXPATHLEN];
	grub_fs_t	gm_fs;
	grub_root_t	gm_root;
};

/* File system helper functions */
int grub_current_root(grub_fs_t *, grub_root_t *);
grub_fsdesc_t *grub_get_rootfsd(const grub_root_t *);
int grub_fsd_mount_tmp(grub_fsdesc_t *, const char *);
void grub_fsd_umount_tmp(grub_fsdesc_t *);
int grub_fsd_get_mountp(grub_fsdesc_t *fsd, char *fstyp);
int grub_find_bootsign(grub_barg_t *barg);


/* GRUB menu parse functions */
int skip_line(const grub_line_t *lp, grub_barg_t *barg);
int error_line(const grub_line_t *lp, grub_barg_t *barg);
int kernel(const grub_line_t *lp, grub_barg_t *barg);
int module(const grub_line_t *lp, grub_barg_t *barg);
int dollar_kernel(const grub_line_t *lp, grub_barg_t *barg);
int dollar_module(const grub_line_t *lp, grub_barg_t *barg);
int findroot(const grub_line_t *lp, grub_barg_t *barg);
int bootfs(const grub_line_t *lp, grub_barg_t *barg);
size_t clean_path(char *path);


/* GRUB entry functions */
int grub_entry_construct_barg(grub_entry_t *ent);
const char *grub_entry_get_fstyp(const grub_entry_t *ent);
const char *grub_entry_get_kernel(const grub_entry_t *ent);
const char *grub_entry_get_module(const grub_entry_t *ent);
const grub_fsdesc_t *grub_entry_get_rootfs(const grub_entry_t *ent);
size_t grub_entry_get_cmdline(grub_entry_t *ent, char *cmdline, size_t size);

/*
 * GRUB menu parse/access funcions.
 *
 * Callers must call grub_menu_init() to to obtain a handle to the menu before
 * calling any of the other functions, and call grub_menu_fini() to close.
 *
 * grub_menu_init:
 *	Reads and parses GRUB menu file into a grub_menu_t data structure.
 *	If grub_menu_path file path is NULL, will use 'currently active'
 *	GRUB menu file.
 * grub_menu_fini:
 *	Frees all resources allocated by grub_menu_init().
 *
 * grub_menu_get_entry:
 *	Returns a particular entry from the menu.
 * grub_menu_next_entry:
 * grub_menu_prev_entry:
 *      Returns next or previous entry in the menu.
 *      If current entry is NULL, return first or last entry.
 *
 * grub_menu_next_line:
 * grub_menu_prev_line:
 *      Returns next/prev (to the current) line in the menu.
 *      If current line is NULL, returns first or last line.
 * grub_menu_get_line:
 *      Returns the specified line in the menu (line counter starts from one).
 */
int grub_menu_init(const char *grub_menu_path, grub_menu_t **menup);
void grub_menu_fini(grub_menu_t *);
grub_entry_t *grub_menu_get_entry(const grub_menu_t *menu, int num);
grub_entry_t *grub_menu_next_entry(const grub_menu_t *menu,
    const grub_entry_t *current);
grub_entry_t *grub_menu_prev_entry(const grub_menu_t *menu,
    const grub_entry_t *current);
grub_line_t *grub_menu_next_line(const grub_menu_t *menu,
    const grub_line_t *current);
grub_line_t *grub_menu_prev_line(const grub_menu_t *menu,
    const grub_line_t *current);

#ifdef __cplusplus
}
#endif

#endif	/* _GRBMIMPL_H */
