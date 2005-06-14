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


#ifndef	_SVM_H
#define	_SVM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#define	RET_SUCCESS	0
#define	RET_ERROR	-1
#define	RET_NOERROR	RET_SUCCESS


#define	PROP_KEEP_REPL_STATE	"md_keep_repl_state"
#define	PROP_DEVID_DESTROY	"md_devid_destroy"

#define	MD_CONF		"/kernel/drv/md.conf"
#define	MD_CONF_ORIG	"/tmp/md.conf.orig"
#define	SYSTEM_FILE	"/etc/system"
#define	NAME_TO_MAJOR	"/etc/name_to_major"
#define	VFSTAB		"/etc/vfstab"

#define	MD_MODULE "md"
#define	ROOT_MNTPT "/"
#define	ROOT_METADEVICE "/dev/md/dsk/"


typedef enum {
	MD_STR_NOTFOUND,	/* bootlist not found */
	MD_STR_START,		/* bootlist found, convertion started */
	MD_STR_DONE		/* bootlist converversion done */
} convflag_t;

/* The following defines have been taken from addrem.h */
#define	MAX_CMD_LINE	256
#define	MAX_N2M_ALIAS_LINE	FILENAME_MAX + FILENAME_MAX + 1
#define	MAXLEN_NAM_TO_MAJ_ENT	FILENAME_MAX + MAX_STR_MAJOR + 1
#define	OPT_LEN	128
#define	CADDR_HEX_STR	16
#define	UINT_STR	10
#define	MODLINE_ENT_MAX	(4 * UINT_STR) + CADDR_HEX_STR + MODMAXNAMELEN
#define	MAX_STR_MAJOR	UINT_STR
#define	STR_LONG	10
#define	PERM_STR	4
#define	MAX_PERM_ENTRY	(2 * STR_LONG) + PERM_STR + (2 * FILENAME_MAX) + 1
#define	MAX_DBFILE_ENTRY	MAX_PERM_ENTRY

extern void create_diskset_links();
extern int copyfile(char *from, char *to);
extern int get_drv_name(major_t major, char *file_name, char *buf);
extern int mod_unload(char *modname);
extern int valid_bootlist(FILE *fp, int line_size);
extern int convert_bootlist(char *systemfile, char *mdconf, char **tmpfilename);
extern int write_xlate_to_mdconf(char *rootpath);
extern int write_targ_nm_table(char *rootpath);
extern int get_rootmetadevice(char *rootpath, char **devname);
extern void set_upgrade_prop(char *prop_name, int val);
extern int is_upgrade_prop(char *prop_name);
extern int create_in_file_prop(char *prop_name, char *fname);
extern void debug_printf(char *fmt, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _SVM_H */
